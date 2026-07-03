package chain

import (
	"errors"
	"testing"

	"github.com/arhuman/prooflog/internal/envelope"
)

// buildChain returns n correctly linked, serialized records as entries.
func buildChain(t *testing.T, n int) []Entry {
	t.Helper()
	entries := make([]Entry, 0, n)
	prev := Genesis
	for i := 1; i <= n; i++ {
		r := envelope.Record{
			Version:      envelope.Version,
			SourceID:     "vps-01/api",
			Seq:          uint64(i),
			EventType:    "system.heartbeat",
			EventTime:    "2026-07-03T12:00:00.000000000Z",
			IngestTime:   "2026-07-03T12:00:00.000000000Z",
			PrevHash:     prev,
			PayloadClear: []byte(`{"i":` + itoa(i) + `}`),
		}
		if err := r.Serialize(); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, Entry{Bytes: r.Bytes(), Hash: r.HashHex()})
		prev = r.HashHex()
	}
	return entries
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestVerifyValidChain(t *testing.T) {
	t.Parallel()
	if err := Verify(buildChain(t, 5)); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
}

func TestVerifyEmpty(t *testing.T) {
	t.Parallel()
	if err := Verify(nil); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}
}

func TestVerifyHashError(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 3)
	entries[1].Hash = "00" + entries[1].Hash[2:]
	var he *HashError
	if err := Verify(entries); !errors.As(err, &he) {
		t.Fatalf("want *HashError, got %v", err)
	}
}

func TestVerifyGapError(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 5)
	// Drop the middle record: seq jumps, prev_hash still links to dropped hash
	// so the gap check must fire first for a monotonicity break.
	spliced := []Entry{entries[0], entries[2], entries[3], entries[4]}
	var ge *GapError
	if err := Verify(spliced); !errors.As(err, &ge) {
		t.Fatalf("want *GapError, got %v", err)
	}
}

func TestVerifyLinkError(t *testing.T) {
	t.Parallel()
	// Two independently-rooted records: both start at Genesis, so seq 2's
	// prev_hash won't link to record 1.
	a := buildChain(t, 1)[0]
	b := buildChain(t, 1)[0] // identical, seq 1, prev Genesis
	_ = b
	entries := buildChain(t, 2)
	// Corrupt record 1's stored prev_hash linkage by swapping record 2's prev.
	bad, err := envelope.Parse(entries[1].Bytes)
	if err != nil {
		t.Fatal(err)
	}
	bad.PrevHash = Genesis
	if err := bad.Serialize(); err != nil {
		t.Fatal(err)
	}
	entries[1] = Entry{Bytes: bad.Bytes(), Hash: bad.HashHex()}
	var le *LinkError
	if err := Verify(entries); !errors.As(err, &le) {
		t.Fatalf("want *LinkError, got %v", err)
	}
	_ = a
}

func TestVerifyFirstMustBeGenesis(t *testing.T) {
	t.Parallel()
	entries := buildChain(t, 2)
	// Start verification from the second record: its prev_hash is not Genesis.
	var le *LinkError
	if err := Verify(entries[1:]); !errors.As(err, &le) {
		t.Fatalf("want *LinkError for non-genesis start, got %v", err)
	}
}
