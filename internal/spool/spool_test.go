package spool

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/arhuman/prooflog/internal/envelope"
)

func makeRec(t *testing.T, seq uint64) envelope.Record {
	t.Helper()
	r := envelope.Record{
		Version:      envelope.Version,
		SourceID:     "vps-01/api",
		Seq:          seq,
		EventType:    "system.heartbeat",
		EventTime:    "2026-07-03T12:00:00.000000000Z",
		IngestTime:   "2026-07-03T12:00:00.000000000Z",
		PayloadClear: []byte(`{"seq":` + strconv.FormatUint(seq, 10) + `}`),
		PrevHash:     envelope.ZeroHash,
	}
	if err := r.Serialize(); err != nil {
		t.Fatal(err)
	}
	return r
}

func openSpool(t *testing.T, dir string) *Spool {
	t.Helper()
	s, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

func TestAppendDurableAndRecover(t *testing.T) {
	dir := t.TempDir()
	s := openSpool(t, dir)
	for i := uint64(1); i <= 5; i++ {
		if err := s.Append(makeRec(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	if s.LastSeq() != 5 {
		t.Fatalf("LastSeq = %d, want 5", s.LastSeq())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopen: LastSeq recovered by scanning.
	s2 := openSpool(t, dir)
	if s2.LastSeq() != 5 {
		t.Fatalf("recovered LastSeq = %d, want 5", s2.LastSeq())
	}
}

func TestAppendRequiresSerialized(t *testing.T) {
	s := openSpool(t, t.TempDir())
	if err := s.Append(envelope.Record{Seq: 1}); err == nil {
		t.Fatal("expected error appending unserialized record")
	}
}

func TestIterFromSeq(t *testing.T) {
	dir := t.TempDir()
	s := openSpool(t, dir)
	for i := uint64(1); i <= 6; i++ {
		if err := s.Append(makeRec(t, i)); err != nil {
			t.Fatal(err)
		}
		if i == 3 {
			if err := s.Roll(); err != nil {
				t.Fatal(err)
			}
		}
	}
	it, err := s.Iter(4)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	var got []uint64
	for {
		rec, ok, err := it.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		got = append(got, rec.Seq)
	}
	want := []uint64{4, 5, 6}
	if len(got) != len(want) {
		t.Fatalf("iter got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("iter got %v, want %v", got, want)
		}
	}
}

func TestRollStartsNewSegmentFile(t *testing.T) {
	dir := t.TempDir()
	s := openSpool(t, dir)
	if err := s.Append(makeRec(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Roll(); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(makeRec(t, 2)); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"+segExt))
	if len(files) != 2 {
		t.Fatalf("want 2 segment files, got %d: %v", len(files), files)
	}
}

func TestMarkAckedPersists(t *testing.T) {
	dir := t.TempDir()
	s := openSpool(t, dir)
	if err := s.Append(makeRec(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAcked(1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s2 := openSpool(t, dir)
	if s2.AckedSeq() != 1 {
		t.Fatalf("recovered AckedSeq = %d, want 1", s2.AckedSeq())
	}
}

func TestTrailingTruncationSelfHeals(t *testing.T) {
	dir := t.TempDir()
	s := openSpool(t, dir)
	for i := uint64(1); i <= 3; i++ {
		if err := s.Append(makeRec(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "*"+segExt))
	fi, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	// Chop the last few bytes: partial trailing frame.
	if err := os.Truncate(files[0], fi.Size()-5); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(Config{Dir: dir})
	if err != nil {
		t.Fatalf("trailing truncation should self-heal, got %v", err)
	}
	if s2.LastSeq() != 2 {
		t.Fatalf("healed LastSeq = %d, want 2", s2.LastSeq())
	}
}

func TestCorruptionInSealedSegment(t *testing.T) {
	dir := t.TempDir()
	s := openSpool(t, dir)
	if err := s.Append(makeRec(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Roll(); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(makeRec(t, 2)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	// Flip a byte inside the first (sealed, non-last) segment's record body.
	files, _ := filepath.Glob(filepath.Join(dir, "*"+segExt))
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	data[3] ^= 0xff
	if err := os.WriteFile(files[0], data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Open(Config{Dir: dir})
	var ce *CorruptionError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CorruptionError, got %v", err)
	}
}

// TestFreeSpaceProbeCached is a white-box check that the real (non-injected)
// probe path reuses one statfs reading within freeSpaceTTL: a burst of appends
// must not statfs per record. cacheFreeSpace is set directly because the public
// Open path only caches the default probe, and injecting a probe (as the other
// pressure tests do) intentionally bypasses the cache.
func TestFreeSpaceProbeCached(t *testing.T) {
	var calls int
	s := &Spool{
		cfg: Config{
			Dir:            t.TempDir(),
			ThresholdBytes: 1000,
			FreeSpace: func(string) (uint64, error) {
				calls++
				return 1 << 30, nil
			},
		},
		cacheFreeSpace: true,
	}
	for i := 0; i < 5; i++ {
		if err := s.enforcePressure(); err != nil {
			t.Fatalf("enforcePressure: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("free-space probe called %d times, want 1 within TTL", calls)
	}
}

func TestPressureBlock(t *testing.T) {
	var pressured uint64
	s, err := Open(Config{
		Dir:            t.TempDir(),
		ThresholdBytes: 1000,
		Policy:         Block,
		OnPressure:     func(free uint64) { pressured = free },
		FreeSpace:      func(string) (uint64, error) { return 500, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(makeRec(t, 1)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("want ErrSpoolFull, got %v", err)
	}
	if pressured != 500 {
		t.Fatalf("OnPressure not called with free bytes, got %d", pressured)
	}
}

func TestPressureDropOldest(t *testing.T) {
	dir := t.TempDir()
	// First, write two acked segments with ample space.
	free := uint64(1 << 30)
	s, err := Open(Config{
		Dir:            dir,
		ThresholdBytes: 1000,
		Policy:         DropOldest,
		FreeSpace:      func(string) (uint64, error) { return free, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(makeRec(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Roll(); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(makeRec(t, 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Roll(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkAcked(1); err != nil {
		t.Fatal(err)
	}
	before, _ := filepath.Glob(filepath.Join(dir, "*"+segExt))
	if len(before) != 2 {
		t.Fatalf("setup: want 2 segments, got %d", len(before))
	}
	// Now simulate disk pressure; the oldest acked segment must be dropped.
	free = 500
	if err := s.Append(makeRec(t, 3)); err != nil {
		t.Fatalf("drop-oldest append failed: %v", err)
	}
	if _, err := os.Stat(before[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oldest acked segment should have been dropped")
	}
}
