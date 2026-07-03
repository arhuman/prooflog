package spool

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// buildSealedSpool writes n single-record sealed segments (seq 1..n) under
// DropOldest with the given FreeSpace probe, leaving the spool open.
func buildSealedSpool(t *testing.T, dir string, n uint64, free func(string) (uint64, error)) *Spool {
	t.Helper()
	s, err := Open(Config{
		Dir:            dir,
		ThresholdBytes: 1000,
		Policy:         DropOldest,
		FreeSpace:      free,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := uint64(1); i <= n; i++ {
		if err := s.Append(makeRec(t, i)); err != nil {
			t.Fatal(err)
		}
		if err := s.Roll(); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// TestDropOldestAfterRestart exercises the recovery-populated cache: after a
// restart the maxSeq cache is rebuilt solely by Open's recovery scan, and
// pressure must still drop acked segments and stop at the first unacked one.
func TestDropOldestAfterRestart(t *testing.T) {
	dir := t.TempDir()
	free := uint64(1 << 30)
	freeFn := func(string) (uint64, error) { return free, nil }

	s := buildSealedSpool(t, dir, 3, freeFn)
	if err := s.MarkAcked(2); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	segs, _ := filepath.Glob(filepath.Join(dir, "*"+segExt))
	if len(segs) != 3 {
		t.Fatalf("setup: want 3 segments, got %d", len(segs))
	}

	// Reopen: cache repopulated by the recovery scan only.
	s2, err := Open(Config{
		Dir:            dir,
		ThresholdBytes: 1000,
		Policy:         DropOldest,
		FreeSpace:      freeFn,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	free = 500
	// First pressured append drops the oldest acked segment (seq 1).
	if err := s2.Append(makeRec(t, 4)); err != nil {
		t.Fatalf("first drop append failed: %v", err)
	}
	if _, err := os.Stat(segs[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oldest acked segment (seq 1) should have been dropped")
	}

	// Second pressured append drops the next acked segment (seq 2).
	if err := s2.Append(makeRec(t, 5)); err != nil {
		t.Fatalf("second drop append failed: %v", err)
	}
	if _, err := os.Stat(segs[1]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("second acked segment (seq 2) should have been dropped")
	}

	// Third pressured append cannot drop: seq 3 is unacked and seq 4/5 are the
	// active segment. enforcePressure must return ErrSpoolFull.
	if err := s2.Append(makeRec(t, 6)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("want ErrSpoolFull with nothing droppable, got %v", err)
	}
	if _, err := os.Stat(segs[2]); err != nil {
		t.Fatalf("unacked segment (seq 3) must not be dropped: %v", err)
	}
}

// TestDropOldestFromCloseActiveCache exercises the same-process cache: segments
// sealed via Roll are dropped from the closeActive-populated cache with no
// restart and no rescan.
func TestDropOldestFromCloseActiveCache(t *testing.T) {
	dir := t.TempDir()
	free := uint64(1 << 30)
	freeFn := func(string) (uint64, error) { return free, nil }

	s := buildSealedSpool(t, dir, 3, freeFn)
	defer s.Close()
	if err := s.MarkAcked(2); err != nil {
		t.Fatal(err)
	}

	segs, _ := filepath.Glob(filepath.Join(dir, "*"+segExt))
	if len(segs) != 3 {
		t.Fatalf("setup: want 3 segments, got %d", len(segs))
	}

	free = 500
	if err := s.Append(makeRec(t, 4)); err != nil {
		t.Fatalf("first drop append failed: %v", err)
	}
	if _, err := os.Stat(segs[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oldest acked segment (seq 1) should have been dropped")
	}

	if err := s.Append(makeRec(t, 5)); err != nil {
		t.Fatalf("second drop append failed: %v", err)
	}
	if _, err := os.Stat(segs[1]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("second acked segment (seq 2) should have been dropped")
	}

	if err := s.Append(makeRec(t, 6)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("want ErrSpoolFull with nothing droppable, got %v", err)
	}
	if _, err := os.Stat(segs[2]); err != nil {
		t.Fatalf("unacked segment (seq 3) must not be dropped: %v", err)
	}
}

// BenchmarkDropOldestPressure measures the Append pressure path over ~50 sealed
// segments. With nothing acked, every Append runs the full drop decision
// (statfs + oldest-segment check) and returns ErrSpoolFull without an fsync,
// isolating the per-append cost: an O(1) cache lookup on the oldest segment
// versus the old O(N) rescan of every sealed segment.
func BenchmarkDropOldestPressure(b *testing.B) {
	dir := b.TempDir()
	free := uint64(1 << 30)
	s, err := Open(Config{
		Dir:            dir,
		ThresholdBytes: 1000,
		Policy:         DropOldest,
		FreeSpace:      func(string) (uint64, error) { return free, nil },
	})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	payload := []byte(`{"x":1}`)
	var seq uint64
	for range 50 {
		for range 3 {
			seq++
			if err := s.Append(makeRecBench(b, seq, payload)); err != nil {
				b.Fatal(err)
			}
		}
		if err := s.Roll(); err != nil {
			b.Fatal(err)
		}
	}

	rec := makeRecBench(b, seq+1, payload)
	free = 500
	b.ReportAllocs()
	for b.Loop() {
		if err := s.Append(rec); !errors.Is(err, ErrSpoolFull) {
			b.Fatalf("want ErrSpoolFull under pressure, got %v", err)
		}
	}
}
