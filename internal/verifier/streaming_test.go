package verifier

import (
	"reflect"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
)

// streamResult drives the public StreamVerifier one frame at a time, exactly as
// the daemon's streamInto does off its pull stream. It is the in-memory
// counterpart of the daemon's streaming path, so a divergence from Verify would
// be a bug in the StreamVerifier wrapper or the fold's order-stability.
func streamResult(src Source, keys Keyring, policy Policy) SourceResult {
	sv := NewStreamVerifier(src, keys, policy)
	for _, e := range src.Entries {
		sv.Add(e)
	}
	return sv.Result()
}

// TestStreamingReproducesVerify is a determinism guard, not a transport oracle:
// it asserts that feeding the public StreamVerifier frame-by-frame reproduces
// Verify's slice-loop SourceResult across the finding-driving scenarios. Both
// sides share the same fold, so this pins order-stability and the wrapper — it
// does NOT prove the gRPC transport preserves semantics. That guarantee is
// covered by package verifierd's real-transport tests (TestRunVerification*),
// which drive tamper, sequence gaps, two checkpoints, and tombstone exemption
// through the actual streamInto/PullSegments/bufconn path and assert concrete
// findings rather than fold-vs-fold equality (P3).
func TestStreamingReproducesVerify(t *testing.T) {
	pubA, privA, keysA := testKeyring(t)
	_ = pubA

	cases := map[string]func(t *testing.T) (Source, Keyring){
		"happy": func(t *testing.T) (Source, Keyring) {
			b := newBuilder(t, privA)
			for i := 0; i < 6; i++ {
				b.heartbeat(20)
				b.tick(60 * time.Second)
			}
			b.seal()
			return b.source(), keysA
		},
		"unobserved_window": func(t *testing.T) (Source, Keyring) {
			b := newBuilder(t, privA)
			b.heartbeat(10)
			b.tick(47 * time.Minute)
			b.heartbeat(10)
			b.seal()
			return b.source(), keysA
		},
		"outage_replay": func(t *testing.T) (Source, Keyring) {
			b := newBuilder(t, privA)
			b.heartbeat(10)
			b.add(evOutage, nil)
			b.tick(8 * time.Minute)
			b.add("access.granted", nil)
			b.add("access.revoked", nil)
			b.add(evReplay, nil)
			b.seal()
			return b.source(), keysA
		},
		"two_checkpoints": func(t *testing.T) (Source, Keyring) {
			b := newBuilder(t, privA)
			b.heartbeat(10)
			b.tick(60 * time.Second)
			b.heartbeat(10)
			b.seal()
			b.tick(60 * time.Second)
			b.heartbeat(2000) // over-drift, drives F-CLOCK
			b.tick(60 * time.Second)
			b.heartbeat(10)
			b.seal()
			return b.source(), keysA
		},
		"tamper": func(t *testing.T) (Source, Keyring) {
			b := newBuilder(t, privA)
			b.heartbeat(10)
			b.tick(60 * time.Second)
			b.heartbeat(10)
			b.seal()
			src := b.source()
			src.Entries[0].Bytes = append([]byte(nil), src.Entries[0].Bytes...)
			src.Entries[0].Bytes[5] ^= 0xff
			return src, keysA
		},
		"tombstoned_gap": func(t *testing.T) (Source, Keyring) {
			b := newBuilder(t, privA)
			for i := 0; i < 3; i++ {
				b.heartbeat(20)
				b.tick(60 * time.Second)
			}
			b.seal()
			firstSegLen := len(b.entries)
			for i := 0; i < 3; i++ {
				b.heartbeat(20)
				b.tick(60 * time.Second)
			}
			b.seal()
			cp1, ok := verifyCheckpointSig(b.checkpts[0], keysA)
			if !ok {
				t.Fatal("first checkpoint should verify")
			}
			src := b.source()
			src.Entries = b.entries[firstSegLen:]
			src.Tombstones = []TombstoneInfo{{
				SegmentID: "seg-1", SeqFirst: 1, SeqLast: 3, Root: cp1.Hash[:], Policy: `{"default_days":30}`,
			}}
			return src, keysA
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			src, keys := build(t)
			want := Verify(src, keys, DefaultPolicy())
			got := streamResult(src, keys, DefaultPolicy())
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("streaming result diverged from Verify:\n want=%+v\n got =%+v", want, got)
			}
		})
	}
}

// TestTombstoneRetroactivelyExemptsEarlierGap proves why verification re-scans
// from genesis every cycle instead of skipping already-verified history: a
// tombstone recorded in a *later* cycle must retroactively exempt a chain gap
// that an *earlier* cycle (before the tombstone existed) would flag as F-CHAIN.
// A full re-scan with the current tombstone set reproduces that exemption; an
// incremental cursor that trusted the earlier verdict could not.
func TestTombstoneRetroactivelyExemptsEarlierGap(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	for i := 0; i < 3; i++ {
		b.heartbeat(20)
		b.tick(60 * time.Second)
	}
	b.seal()
	firstSegLen := len(b.entries)
	for i := 0; i < 3; i++ {
		b.heartbeat(20)
		b.tick(60 * time.Second)
	}
	b.seal()

	cp1, ok := verifyCheckpointSig(b.checkpts[0], keys)
	if !ok {
		t.Fatal("first checkpoint should verify")
	}
	// The first segment's blob is gone; only the tail survives, its seq starting
	// past the deleted range.
	retained := b.entries[firstSegLen:]

	// Cycle 1: the tombstone has not been recorded yet. The tail no longer links
	// to genesis, so the chain breaks and F-CHAIN is emitted.
	cycle1 := Source{SourceID: srcID, Origin: origin, Entries: retained, Checkpoints: b.checkpts}
	res1 := Verify(cycle1, keys, DefaultPolicy())
	if res1.Chain.Valid || !hasFinding(res1.Findings, "F-CHAIN") {
		t.Fatalf("cycle 1 (no tombstone) must flag the gap as F-CHAIN: %+v", res1.Findings)
	}

	// Cycle 2: the retention tombstone is now present, covering the deleted range.
	// A full re-scan exempts the same gap and the source verifies clean.
	cycle2 := cycle1
	cycle2.Tombstones = []TombstoneInfo{{
		SegmentID: "seg-1", SeqFirst: 1, SeqLast: 3, Root: cp1.Hash[:], Policy: `{"default_days":30}`,
	}}
	res2 := Verify(cycle2, keys, DefaultPolicy())
	if !res2.Chain.Valid || hasFinding(res2.Findings, "F-CHAIN") {
		t.Fatalf("cycle 2 (tombstone recorded) must retroactively exempt the gap: %+v", res2.Findings)
	}
	// The streaming daemon path reproduces the exempted verdict exactly.
	if got := streamResult(cycle2, keys, DefaultPolicy()); !reflect.DeepEqual(res2, got) {
		t.Fatalf("streaming diverged on tombstone exemption:\n want=%+v\n got =%+v", res2, got)
	}
}

// TestLargeSourceNoCliff verifies a source strictly larger than the old maxPull
// hard limit (1<<20 frames). The pre-P3 daemon returned a verification FAILURE
// past that many frames; the streaming fold now completes with a valid chain and
// no findings, retaining no frame slice (memory is O(1) in the raw frames).
func TestLargeSourceNoCliff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping >1M-frame cliff test in -short mode")
	}
	const n = uint64(1<<20) + 1 // one frame past the old maxPull cliff
	_, _, keys := testKeyring(t)

	// No checkpoints and no tombstones: this isolates the unbounded chain fold that
	// used to trip the cliff. Frames are generated lazily and discarded after each
	// add, so nothing here materialises all n frames.
	fold := newSourceFold(srcID, origin, nil, nil, nil, keys, DefaultPolicy())
	prev := envelope.ZeroHash
	now := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	for i := uint64(1); i <= n; i++ {
		rec := envelope.Record{
			Version:      envelope.Version,
			SourceID:     srcID,
			Seq:          i,
			EventType:    evHeartbeat,
			EventTime:    envelope.FormatTime(now),
			IngestTime:   envelope.FormatTime(now),
			PrevHash:     prev,
			PayloadClear: []byte(`{}`),
		}
		if err := rec.Serialize(); err != nil {
			t.Fatal(err)
		}
		fold.add(chain.Entry{Bytes: rec.Bytes(), Hash: rec.HashHex()})
		prev = rec.HashHex()
		now = now.Add(60 * time.Second)
	}

	res := fold.result()
	if !res.Chain.Valid {
		t.Fatalf("large source chain must stay valid past the old maxPull: %v", res.Chain.Err)
	}
	if res.SeqLast != n {
		t.Fatalf("seq_last = %d, want %d", res.SeqLast, n)
	}
	if hasFinding(res.Findings, "F-CHAIN") {
		t.Fatalf("clean large source must not raise F-CHAIN: %+v", res.Findings)
	}
}
