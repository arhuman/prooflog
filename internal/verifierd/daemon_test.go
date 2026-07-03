package verifierd

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/arhuman/prooflog/internal/anchor/tsatest"
	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/verifier"
)

func TestSubmitCheckpointAcceptsAndPersists(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.heartbeat(10)
	b.seal()
	d := newDaemon(t, newRegistry(t, pub), nil)

	ack, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: b.checkpts[0], SourceId: srcID})
	if err != nil {
		t.Fatal(err)
	}
	if !ack.Accepted {
		t.Fatal("checkpoint should be accepted")
	}
	if _, ok := d.cps.LastFor(origin); !ok {
		t.Fatal("head not tracked after accept")
	}
	all, err := d.cps.All(srcID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("persisted %d notes, want 1", len(all))
	}
}

func TestSubmitRejectsUnregisteredSource(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.seal()
	d := newDaemon(t, newRegistry(t, pub), nil)
	_, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: b.checkpts[0], SourceId: "other/src"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func TestSubmitRejectsBadSignature(t *testing.T) {
	pub, _, _ := testKeyring(t)
	_, otherPriv, _ := testKeyring(t)
	// Sign with a key not matching the registered public key.
	forged := signedCP(t, otherPriv, 1, [32]byte{})
	d := newDaemon(t, newRegistry(t, pub), nil)
	_, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: forged, SourceId: srcID})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}

func TestSubmitRejectsEquivocationFork(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.heartbeat(10)
	b.seal() // real checkpoint at size 2
	d := newDaemon(t, newRegistry(t, pub), nil)
	if _, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: b.checkpts[0], SourceId: srcID}); err != nil {
		t.Fatal(err)
	}
	// A different root at the same size 2 is a fork.
	fork := signedCP(t, priv, 2, [32]byte{0xDE, 0xAD})
	_, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: fork, SourceId: srcID})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
}

func TestSubmitRejectsRollback(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	for i := 0; i < 4; i++ {
		b.heartbeat(10)
	}
	b.seal() // size 4
	d := newDaemon(t, newRegistry(t, pub), nil)
	if _, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: b.checkpts[0], SourceId: srcID}); err != nil {
		t.Fatal(err)
	}
	rollback := signedCP(t, priv, 2, [32]byte{0x01})
	_, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: rollback, SourceId: srcID})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
}

func TestSubmitIdempotent(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.seal()
	d := newDaemon(t, newRegistry(t, pub), nil)
	note0 := &api.SignedNote{Note: b.checkpts[0], SourceId: srcID}
	if _, err := d.SubmitCheckpoint(context.Background(), note0); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SubmitCheckpoint(context.Background(), note0); err != nil {
		t.Fatalf("idempotent resubmission should succeed: %v", err)
	}
	all, _ := d.cps.All(srcID)
	if len(all) != 1 {
		t.Fatalf("idempotent resubmit persisted %d notes, want 1", len(all))
	}
}

func TestCheckpointStorePersistenceAcrossReopen(t *testing.T) {
	_, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.heartbeat(10)
	b.seal()
	dir := t.TempDir()

	c1, err := verifier.OpenCheckpointStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := verifier.CheckpointOf(b.checkpts[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.Accept(srcID, b.checkpts[0], cp); err != nil {
		t.Fatal(err)
	}

	c2, err := verifier.OpenCheckpointStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := c2.LastFor(origin)
	if !ok || got.Size != cp.Size || got.Hash != cp.Hash {
		t.Fatalf("head not recovered: %+v ok=%v", got, ok)
	}
	// A fork must be rejected after reopening (head survived restart).
	fork := signedCP(t, priv, cp.Size, [32]byte{0x09})
	fcp, _ := verifier.CheckpointOf(fork)
	if err := c2.Accept(srcID, fork, fcp); err == nil {
		t.Fatal("fork accepted after reopen")
	}
}

func TestRunVerificationEndToEnd(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	for i := 0; i < 5; i++ {
		b.heartbeat(10)
		b.tick(60 * time.Second)
	}
	b.seal()

	storeClient := bufconnStore(t, segUpload{seqFirst: 1, entries: b.entries})
	d := newDaemon(t, newRegistry(t, pub), storeClient)
	if _, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: b.checkpts[0], SourceId: srcID}); err != nil {
		t.Fatal(err)
	}

	if err := d.RunVerification(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, ok := d.Results()[srcID]
	if !ok {
		t.Fatal("no result cached for source")
	}
	if !res.Chain.Valid || !res.Checkpoints.Consistent || res.Checkpoints.RootsValid != 1 {
		t.Fatalf("verification not clean: %+v", res.Checkpoints)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
}

// TestAnchorLoopBatching asserts the time-based batching contract: three
// accepted checkpoints yield exactly one receipt per anchor tick, an idle tick
// (no head advance) yields none, and a later head advance yields one more.
func TestAnchorLoopBatching(t *testing.T) {
	pub, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.heartbeat(10)
	b.seal() // size 2
	b.heartbeat(10)
	b.seal() // size 3
	b.heartbeat(10)
	b.seal() // size 4

	dir := t.TempDir()
	fake := &tsatest.FakeAnchor{GenTime: time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)}
	d, err := NewDaemon(DaemonConfig{Registry: newRegistry(t, pub), DataDir: dir, Anchor: fake})
	if err != nil {
		t.Fatal(err)
	}
	for _, cp := range b.checkpts {
		if _, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: cp, SourceId: srcID}); err != nil {
			t.Fatal(err)
		}
	}

	// One tick over three accepted checkpoints → exactly one receipt (the head).
	if err := d.RunAnchoring(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := d.anchorLog.All(srcID)
	if len(got) != 1 {
		t.Fatalf("first tick anchored %d receipts, want 1", len(got))
	}
	if got[0].Size != 4 {
		t.Fatalf("anchored size = %d, want 4 (the head)", got[0].Size)
	}

	// Idle tick: head has not advanced → no new receipt.
	if err := d.RunAnchoring(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.anchorLog.All(srcID); len(got) != 1 {
		t.Fatalf("idle tick anchored extra receipts: %d", len(got))
	}

	// Head advances → one more receipt.
	b.heartbeat(10)
	b.seal() // size 5
	if _, err := d.SubmitCheckpoint(context.Background(), &api.SignedNote{Note: b.checkpts[3], SourceId: srcID}); err != nil {
		t.Fatal(err)
	}
	if err := d.RunAnchoring(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ = d.anchorLog.All(srcID)
	if len(got) != 2 || got[1].Size != 5 {
		t.Fatalf("after advance: %d receipts (last size %d), want 2 ending at size 5", len(got), got[len(got)-1].Size)
	}
}
