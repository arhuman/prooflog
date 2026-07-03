package agent

import (
	"encoding/base64"
	"testing"

	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/verifier"
)

// drainCheckpoints reads all buffered sealed checkpoints without blocking. The
// agent is not Started in these tests, so enqueue only buffers the channels.
func drainCheckpoints(a *Agent) []string {
	var cps []string
	for {
		select {
		case s := <-a.checkpointCh:
			cps = append(cps, s.Checkpoint)
		default:
			return cps
		}
	}
}

// TestAgentRotateKeyVerifiesClean drives a real Agent through a mid-stream key
// rotation and proves the resulting chain + checkpoints verify with NO findings
// once both public keys are registered. It exercises the whole RotateKey path:
// emit system.key_rotated, seal under the old key, persist and swap to the new
// key, keep sealing under the new key.
func TestAgentRotateKeyVerifiesClean(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000) // high seal threshold: we control seals
	defer a.Stop()

	oldName := a.agentKey.Name
	oldPub := a.agentKey.Public

	for i := 0; i < 2; i++ {
		if _, err := a.Heartbeat(); err != nil {
			t.Fatal(err)
		}
	}

	res, err := a.RotateKey("scheduled rotation")
	if err != nil {
		t.Fatal(err)
	}
	if res.NewKeyName == oldName {
		t.Fatalf("new key name must differ from old (%q)", oldName)
	}

	// The rotated key was persisted to the key path under its new name.
	reloaded, err := keys.LoadAgentKey(a.cfg.AgentKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Name != res.NewKeyName {
		t.Fatalf("persisted key name = %q, want %q", reloaded.Name, res.NewKeyName)
	}

	// More activity under the new key, then force a final seal.
	for i := 0; i < 2; i++ {
		if _, err := a.Heartbeat(); err != nil {
			t.Fatal(err)
		}
	}
	a.Flush()

	// Assemble the offline verification inputs from the agent's own spool and the
	// checkpoints it sealed.
	entries := spooledEntries(t, a)
	if err := chain.Verify(entries); err != nil {
		t.Fatalf("rotation must not break the chain: %v", err)
	}

	// A system.key_rotated event is present in the chain.
	if !containsEvent(t, entries, EventKeyRotated) {
		t.Fatal("expected a system.key_rotated event in the chain")
	}

	checkpoints := drainCheckpoints(a)
	if len(checkpoints) < 2 {
		t.Fatalf("expected at least 2 checkpoints (old key + new key), got %d", len(checkpoints))
	}

	newPub, err := base64.StdEncoding.DecodeString(res.NewPublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	ring := verifier.Keyring{oldName: oldPub, res.NewKeyName: newPub}

	src := verifier.Source{
		SourceID:    a.cfg.SourceID,
		Origin:      res.Origin,
		Entries:     entries,
		Checkpoints: checkpoints,
	}
	vres := verifier.Verify(src, ring, verifier.DefaultPolicy())
	if len(vres.Findings) != 0 {
		t.Fatalf("rotated agent chain must verify clean, findings: %+v", vres.Findings)
	}
	if vres.Checkpoints.Total != vres.Checkpoints.SignaturesValid ||
		vres.Checkpoints.SignaturesValid != vres.Checkpoints.RootsValid ||
		vres.Checkpoints.Total < 2 {
		t.Fatalf("checkpoints not all valid across rotation: %+v", vres.Checkpoints)
	}
}

// TestAgentRevokeKeyRecordsBoundary proves RevokeKey emits a system.key_revoked
// event that carries the current key id and, when offline-verified, yields an
// F-KEYREV finding while leaving the chain valid.
func TestAgentRevokeKeyRecordsBoundary(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()

	name := a.agentKey.Name
	pub := a.agentKey.Public

	if _, err := a.Heartbeat(); err != nil {
		t.Fatal(err)
	}
	rec, err := a.RevokeKey("laptop stolen", "2026-07-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if rec.EventType != EventKeyRevoked {
		t.Fatalf("event type = %q, want %q", rec.EventType, EventKeyRevoked)
	}
	a.Flush()

	entries := spooledEntries(t, a)
	checkpoints := drainCheckpoints(a)
	ring := verifier.Keyring{name: pub}
	src := verifier.Source{SourceID: a.cfg.SourceID, Origin: a.origin, Entries: entries, Checkpoints: checkpoints}
	vres := verifier.Verify(src, ring, verifier.DefaultPolicy())

	if !vres.Chain.Valid {
		t.Fatalf("revocation must not break the chain: %v", vres.Chain.Err)
	}
	var found bool
	for _, f := range vres.Findings {
		if f.ID == "F-KEYREV" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected F-KEYREV finding, got: %+v", vres.Findings)
	}
}

func containsEvent(t *testing.T, entries []chain.Entry, eventType string) bool {
	t.Helper()
	for _, e := range entries {
		rec, err := envelope.Parse(e.Bytes)
		if err != nil {
			continue
		}
		if rec.EventType == eventType {
			return true
		}
	}
	return false
}
