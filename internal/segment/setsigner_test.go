package segment

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/note"
)

// TestSetSignerKeepsTree seals a segment under key A, swaps the signer to key B
// with SetSigner, and seals again. The second checkpoint must verify under B and
// the first under A, while the Merkle tree continues unbroken: the second seal's
// tree size includes the first seal's leaves. This is the crypto foundation of
// clean key rotation (REQ-C-07, REQ-C-11).
func TestSetSignerKeepsTree(t *testing.T) {
	t.Parallel()
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const origin = "prooflog/acme/vps-01/api"
	now := time.Unix(0, 0)
	b := New(origin, "vps-01-api", privA)

	if err := b.Add([]byte("rec-1"), 1, now); err != nil {
		t.Fatal(err)
	}
	if err := b.Add([]byte("rec-2"), 2, now); err != nil {
		t.Fatal(err)
	}
	first, err := b.Seal(now)
	if err != nil {
		t.Fatal(err)
	}
	if first.TreeSize != 2 {
		t.Fatalf("first tree size = %d, want 2", first.TreeSize)
	}

	// Rotate to key B; the tree and sealed offset are untouched.
	b.SetSigner("vps-01-api-g2", privB)

	if err := b.Add([]byte("rec-3"), 3, now); err != nil {
		t.Fatal(err)
	}
	second, err := b.Seal(now)
	if err != nil {
		t.Fatal(err)
	}
	if second.TreeSize != 3 {
		t.Fatalf("second tree size = %d, want 3 (tree must continue)", second.TreeSize)
	}
	if second.SeqFirst != 3 {
		t.Fatalf("second seq first = %d, want 3", second.SeqFirst)
	}

	// The first checkpoint verifies under A and not under B.
	if _, err := note.Verify(first.Checkpoint, "vps-01-api", pubA); err != nil {
		t.Fatalf("first checkpoint must verify under key A: %v", err)
	}
	if _, err := note.Verify(first.Checkpoint, "vps-01-api-g2", pubB); err == nil {
		t.Fatal("first checkpoint must NOT verify under key B")
	}
	// The second checkpoint verifies under B and not under A.
	if _, err := note.Verify(second.Checkpoint, "vps-01-api-g2", pubB); err != nil {
		t.Fatalf("second checkpoint must verify under key B: %v", err)
	}
	if _, err := note.Verify(second.Checkpoint, "vps-01-api", pubA); err == nil {
		t.Fatal("second checkpoint must NOT verify under key A")
	}
}
