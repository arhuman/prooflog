package verifierd

import (
	"context"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/api"
)

// The tests below drive real verification cycles through the daemon's actual
// streamInto/PullSegments/bufconn path and assert the concrete findings each
// scenario must produce. They replace the former fold-vs-fold "oracle": negative
// cases (tamper, sequence gap, tombstone exemption) now cross the real gRPC
// transport, not just the in-memory fold. The positive determinism guard that
// the streaming fold reproduces Verify lives in package verifier's
// TestStreamingReproducesVerify.

// TestRunVerificationDetectsTamper corrupts one record's bytes on the wire (the
// production store rejects such a frame on upload, so a controllable server
// injects it) and asserts the daemon surfaces a broken chain as F-CHAIN.
func TestRunVerificationDetectsTamper(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.heartbeat(10)

	frames := framesOf(t, b.entries)
	corrupt := append([]byte(nil), frames[0].RecordBytes...)
	corrupt[5] ^= 0xff // hash no longer matches the frame's stored RecordHash
	frames[0].RecordBytes = corrupt

	d := newDaemon(t, newRegistry(t, pub), fakeStoreClient(t, &fakeStore{frames: frames}))
	if err := d.RunVerification(context.Background()); err != nil {
		t.Fatal(err)
	}
	res := d.Results()[srcID]
	if res.Chain.Valid {
		t.Fatal("tampered record must break the chain")
	}
	if !hasFinding(res.Findings, "F-CHAIN") {
		t.Fatalf("expected F-CHAIN, got %+v", res.Findings)
	}
}

// TestRunVerificationSequenceGap serves two non-contiguous segments (seq 1-2 and
// seq 4-5, with seq 3 absent and no tombstone) through the real store and
// asserts the daemon flags the missing seq as F-CHAIN.
func TestRunVerificationSequenceGap(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	for i := 0; i < 5; i++ {
		b.heartbeat(10)
		b.tick(60 * time.Second)
	}
	storeClient := bufconnStore(t,
		segUpload{seqFirst: 1, entries: b.entries[0:2]},
		segUpload{seqFirst: 4, entries: b.entries[3:5]},
	)
	d := newDaemon(t, newRegistry(t, pub), storeClient)
	if err := d.RunVerification(context.Background()); err != nil {
		t.Fatal(err)
	}
	res := d.Results()[srcID]
	if res.Chain.Valid {
		t.Fatal("a seq gap with no tombstone must break the chain")
	}
	if !hasFinding(res.Findings, "F-CHAIN") {
		t.Fatalf("expected F-CHAIN for the seq gap, got %+v", res.Findings)
	}
}

// TestRunVerificationTwoCheckpoints streams a source with two accepted
// checkpoints through the real store and asserts both roots recompute (RootsValid
// == 2), the checkpoints stay consistent, and no findings are raised.
func TestRunVerificationTwoCheckpoints(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.seal() // size 2
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.seal() // size 4

	storeClient := bufconnStore(t, segUpload{seqFirst: 1, entries: b.entries})
	d := newDaemon(t, newRegistry(t, pub), storeClient)
	for _, cp := range b.checkpts {
		if _, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: cp, SourceId: srcID}); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.RunVerification(context.Background()); err != nil {
		t.Fatal(err)
	}
	res := d.Results()[srcID]
	if res.Checkpoints.Total != 2 || res.Checkpoints.RootsValid != 2 {
		t.Fatalf("checkpoint check = %+v, want total=2 rootsvalid=2", res.Checkpoints)
	}
	if !res.Checkpoints.Consistent {
		t.Fatal("append-only checkpoints must be consistent")
	}
	if len(res.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
}

// TestRunVerificationTombstoneExemptsGap drives the retention-exemption path
// end-to-end: the first segment's blob is gone, only the seq 4-6 tail is served,
// and a tombstone (bound to the first checkpoint's root) covers seq 1-3. The
// daemon must exempt the resulting gap (chain stays valid, no F-CHAIN) and report
// the deleted range as verifiable-by-commitment (RootsRetained, no F-RETENTION).
func TestRunVerificationTombstoneExemptsGap(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	for i := 0; i < 3; i++ {
		b.heartbeat(20)
		b.tick(60 * time.Second)
	}
	b.seal() // checkpoint over seq 1-3
	firstSegLen := len(b.entries)
	for i := 0; i < 3; i++ {
		b.heartbeat(20)
		b.tick(60 * time.Second)
	}
	b.seal()

	cp1Root := checkpointRootFor(t, b.checkpts[0], pub)
	retained := b.entries[firstSegLen:] // seq 4-6; seq 1-3 deleted by retention
	fs := &fakeStore{
		frames: framesOf(t, retained),
		tombstones: []*api.Tombstone{{
			SegmentId: "seg-1", SeqFirst: 1, SeqLast: 3, Root: cp1Root[:],
			Policy: `{"default_days":30}`,
		}},
	}
	d := newDaemon(t, newRegistry(t, pub), fakeStoreClient(t, fs))
	// Accept the first checkpoint so the tombstone's root ties to committed history.
	if _, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: b.checkpts[0], SourceId: srcID}); err != nil {
		t.Fatal(err)
	}
	if err := d.RunVerification(context.Background()); err != nil {
		t.Fatal(err)
	}
	res := d.Results()[srcID]
	if !res.Chain.Valid || hasFinding(res.Findings, "F-CHAIN") {
		t.Fatalf("tombstone must exempt the gap: chain=%+v findings=%+v", res.Chain, res.Findings)
	}
	if res.Retention.ExpiredSegments != 1 || !res.Retention.RootsRetained {
		t.Fatalf("retention summary = %+v, want 1 expired segment with roots retained", res.Retention)
	}
	if hasFinding(res.Findings, "F-RETENTION") {
		t.Fatalf("a committed tombstone root must not raise F-RETENTION: %+v", res.Findings)
	}
}
