package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// TestRotatedChainVerifiesClean is the core correctness property: a source that
// rotates its signing key mid-stream verifies with NO findings when both public
// keys are registered. The Merkle tree continues unbroken across the rotation,
// the checkpoint covering the key_rotated event is sealed under the OLD key, and
// later checkpoints are sealed under the NEW key — each verifies against
// whichever key signed it (REQ-C-07, REQ-C-11).
func TestRotatedChainVerifiesClean(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const newKeyName = keyName + "-g2"

	b := newBuilder(t, privA) // seals under keyName + privA

	// Pre-rotation activity, sealed under the old key.
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.seal()

	// The handoff: emit key_rotated as a leaf, then seal it under the OLD key so
	// the outgoing key attests the change.
	b.add(evKeyRotated, map[string]any{
		"old_key_id":   "aaaaaaaa",
		"old_key_name": keyName,
		"new_key_id":   "bbbbbbbb",
		"new_key_name": newKeyName,
		"reason":       "scheduled rotation",
	})
	b.seal()

	// Swap the signer; every later checkpoint is signed by the new key.
	b.batcher.SetSigner(newKeyName, privB)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.seal()

	// Both public keys are registered, keyed by their distinct names.
	ring := Keyring{keyName: pubA, newKeyName: pubB}
	res := Verify(b.source(), ring, DefaultPolicy())

	if len(res.Findings) != 0 {
		t.Fatalf("rotated chain must verify clean, got findings: %+v", res.Findings)
	}
	if !res.Chain.Valid {
		t.Fatalf("chain must stay valid across rotation: %v", res.Chain.Err)
	}
	if res.Checkpoints.Total != 3 || res.Checkpoints.SignaturesValid != 3 || res.Checkpoints.RootsValid != 3 {
		t.Fatalf("checkpoints: %+v, want 3 total/valid signatures/valid roots", res.Checkpoints)
	}
	if !res.Checkpoints.Consistent {
		t.Fatal("checkpoints must be consistent across rotation")
	}
}

// TestRotatedChainFailsWithoutNewKey guards the property from the other side:
// drop the new key from the registry and the post-rotation checkpoint must fail
// signature verification (proving the multi-key registration is what makes the
// rotated chain clean, not a weakened check).
func TestRotatedChainFailsWithoutNewKey(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	_, privB, _ := ed25519.GenerateKey(rand.Reader)
	const newKeyName = keyName + "-g2"

	b := newBuilder(t, privA)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.seal()
	b.batcher.SetSigner(newKeyName, privB)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.seal()

	// Only the OLD key registered.
	res := Verify(b.source(), Keyring{keyName: pubA}, DefaultPolicy())
	if res.Checkpoints.SignaturesValid == res.Checkpoints.Total {
		t.Fatal("expected the new-key checkpoint to fail without its public key registered")
	}
	var hasSig bool
	for _, f := range res.Findings {
		if f.ID == "F-SIG" {
			hasSig = true
		}
	}
	if !hasSig {
		t.Fatal("expected F-SIG when the rotated-to key is unregistered")
	}
}

// TestKeyRevokedYieldsFinding proves a system.key_revoked event in the source's
// own chain surfaces as an F-KEYREV finding while leaving the chain valid — the
// revocation records a trust boundary, it does not break continuity.
func TestKeyRevokedYieldsFinding(t *testing.T) {
	_, priv, ring := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.add(evKeyRevoked, map[string]any{
		"revoked_key_id":   "deadbeef",
		"revoked_key_name": keyName,
		"reason":           "laptop stolen",
		"suspected_since":  "2026-07-01T00:00:00Z",
	})
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.seal()

	res := Verify(b.source(), ring, DefaultPolicy())
	if !res.Chain.Valid {
		t.Fatalf("revocation must not break the chain: %v", res.Chain.Err)
	}
	if len(res.Revocations) != 1 {
		t.Fatalf("expected 1 recorded revocation, got %d", len(res.Revocations))
	}

	var rev string
	for _, f := range res.Findings {
		if f.ID == "F-KEYREV" {
			rev = f.Detail
		}
	}
	if rev == "" {
		t.Fatalf("expected an F-KEYREV finding, findings: %+v", res.Findings)
	}
	if !strings.Contains(rev, "deadbeef") || !strings.Contains(rev, "laptop stolen") ||
		!strings.Contains(rev, "2026-07-01T00:00:00Z") {
		t.Fatalf("F-KEYREV detail missing key id/reason/window: %q", rev)
	}
}
