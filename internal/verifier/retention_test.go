package verifier

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestVerifyTombstonedRangeNoGap(t *testing.T) {
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
	retained := b.entries[firstSegLen:]
	src := b.source()
	src.Entries = retained
	src.Tombstones = []TombstoneInfo{{
		SegmentID: "seg-1", SeqFirst: 1, SeqLast: 3, Root: cp1.Hash[:], Policy: `{"default_days":30}`,
	}}

	res := Verify(src, keys, DefaultPolicy())
	if !res.Chain.Valid {
		t.Fatalf("chain should tolerate the tombstoned gap: %v", res.Chain.Err)
	}
	if res.Retention.ExpiredSegments != 1 {
		t.Fatalf("want 1 expired segment, got %d", res.Retention.ExpiredSegments)
	}
	if !res.Retention.RootsRetained {
		t.Fatal("tombstone root matches an accepted checkpoint; RootsRetained should be true")
	}
	if len(res.Retention.ExpiredRanges) != 1 || res.Retention.ExpiredRanges[0] != "seq 1-3" {
		t.Fatalf("unexpected expired ranges: %v", res.Retention.ExpiredRanges)
	}
	if hasFinding(res.Findings, "F-CHAIN") || hasFindingPrefix(res, "F-GAP") || hasFinding(res.Findings, "F-RETENTION") {
		t.Fatalf("legitimate retention deletion must not raise F-CHAIN/F-GAP/F-RETENTION: %+v", res.Findings)
	}
}

func TestVerifyTombstoneAlienRootRaisesFinding(t *testing.T) {
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

	alien := make([]byte, 32)
	if _, err := rand.Read(alien); err != nil {
		t.Fatal(err)
	}
	src := b.source()
	src.Entries = b.entries[firstSegLen:]
	src.Tombstones = []TombstoneInfo{{
		SegmentID: "seg-1", SeqFirst: 1, SeqLast: 3, Root: alien, Policy: `{"default_days":30}`,
	}}

	res := Verify(src, keys, DefaultPolicy())
	if res.Retention.RootsRetained {
		t.Fatal("an alien tombstone root must not be reported as retained")
	}
	if !hasFinding(res.Findings, "F-RETENTION") {
		t.Fatalf("alien tombstone root must raise F-RETENTION: %+v", res.Findings)
	}
}

func hasFindingPrefix(res SourceResult, prefix string) bool {
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, prefix) {
			return true
		}
	}
	return false
}
