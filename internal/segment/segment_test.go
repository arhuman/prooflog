package segment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/merkle"
	"github.com/arhuman/prooflog/internal/note"
)

func TestNewIDStructure(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(0x0123456789A)
	id, err := NewID(now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if v := id[6] >> 4; v != 7 {
		t.Fatalf("version nibble = %d, want 7", v)
	}
	if variant := id[8] >> 6; variant != 0b10 {
		t.Fatalf("variant bits = %b, want 10", variant)
	}
	// The 48-bit timestamp is big-endian unix-ms.
	ms := uint64(id[0])<<40 | uint64(id[1])<<32 | uint64(id[2])<<24 |
		uint64(id[3])<<16 | uint64(id[4])<<8 | uint64(id[5])
	if ms != uint64(now.UnixMilli()) {
		t.Fatalf("embedded ms = %d, want %d", ms, now.UnixMilli())
	}
}

func TestNewIDTimeOrdered(t *testing.T) {
	t.Parallel()
	a, _ := NewID(time.UnixMilli(1000), rand.Reader)
	b, _ := NewID(time.UnixMilli(2000), rand.Reader)
	if bytes.Compare(a[:], b[:]) >= 0 {
		t.Fatal("earlier UUIDv7 should sort before later one")
	}
}

func TestIDString(t *testing.T) {
	t.Parallel()
	var id ID
	for i := range id {
		id[i] = byte(i)
	}
	got := id.String()
	want := "00010203-0405-0607-0809-0a0b0c0d0e0f"
	if got != want {
		t.Fatalf("String = %s, want %s", got, want)
	}
}

func newBatcher(t *testing.T, opts ...Option) (*Batcher, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name := "vps-01-api"
	return New("prooflog/acme/vps-01/api", name, priv, opts...), pub, name
}

func TestAddContiguity(t *testing.T) {
	t.Parallel()
	b, _, _ := newBatcher(t)
	now := time.Now()
	if err := b.Add([]byte("r1"), 1, now); err != nil {
		t.Fatal(err)
	}
	if err := b.Add([]byte("r3"), 3, now); err == nil {
		t.Fatal("expected non-contiguous seq error")
	}
}

func TestReadyThresholds(t *testing.T) {
	t.Parallel()
	start := time.Unix(0, 0)
	t.Run("by count", func(t *testing.T) {
		b, _, _ := newBatcher(t, WithMaxRecords(3), WithMaxAge(time.Hour))
		for i := 1; i <= 2; i++ {
			_ = b.Add([]byte{byte(i)}, uint64(i), start)
		}
		if b.Ready(start) {
			t.Fatal("not ready below count threshold")
		}
		_ = b.Add([]byte{3}, 3, start)
		if !b.Ready(start) {
			t.Fatal("ready at count threshold")
		}
	})
	t.Run("by age", func(t *testing.T) {
		b, _, _ := newBatcher(t, WithMaxRecords(1000), WithMaxAge(60*time.Second))
		_ = b.Add([]byte{1}, 1, start)
		if b.Ready(start.Add(59 * time.Second)) {
			t.Fatal("not ready before age threshold")
		}
		if !b.Ready(start.Add(60 * time.Second)) {
			t.Fatal("ready at age threshold")
		}
	})
	t.Run("empty never ready", func(t *testing.T) {
		b, _, _ := newBatcher(t)
		if b.Ready(start.Add(time.Hour)) {
			t.Fatal("empty batcher must not be ready")
		}
	})
}

func TestSealProducesVerifiableCheckpoint(t *testing.T) {
	t.Parallel()
	b, pub, name := newBatcher(t, WithMaxRecords(2), WithMaxAge(time.Hour))
	now := time.Now()
	entries := [][]byte{[]byte("record-1"), []byte("record-2")}
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		if err := b.Add(e, uint64(i+1), now); err != nil {
			t.Fatal(err)
		}
		leaves[i] = merkle.LeafHash(e)
	}
	sealed, err := b.Seal(now)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.SeqFirst != 1 || sealed.SeqLast != 2 || sealed.TreeSize != 2 {
		t.Fatalf("bad seq range: %+v", sealed)
	}
	if sealed.Root != merkle.Root(leaves) {
		t.Fatal("sealed root != merkle root over leaves")
	}
	// The checkpoint is a valid signed note carrying the tree root.
	text, err := note.Verify(sealed.Checkpoint, name, pub)
	if err != nil {
		t.Fatalf("checkpoint signature invalid: %v", err)
	}
	cp, err := note.ParseCheckpoint(text)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Origin != sealed.Origin || cp.Size != sealed.TreeSize || cp.Hash != sealed.Root {
		t.Fatalf("checkpoint mismatch: %+v", cp)
	}
	// A record in the segment proves inclusion against the checkpoint root.
	proof := merkle.InclusionProof(leaves, 0)
	if !merkle.VerifyInclusion(leaves[0], 0, int(sealed.TreeSize), proof, sealed.Root) {
		t.Fatal("inclusion proof against checkpoint root failed")
	}
}

func TestSealAcrossMultipleSegments(t *testing.T) {
	t.Parallel()
	b, _, _ := newBatcher(t, WithMaxRecords(2), WithMaxAge(time.Hour))
	now := time.Now()
	_ = b.Add([]byte("a"), 1, now)
	_ = b.Add([]byte("b"), 2, now)
	s1, err := b.Seal(now)
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Add([]byte("c"), 3, now)
	_ = b.Add([]byte("d"), 4, now)
	s2, err := b.Seal(now)
	if err != nil {
		t.Fatal(err)
	}
	if s1.SeqFirst != 1 || s1.SeqLast != 2 {
		t.Fatalf("segment 1 range: %+v", s1)
	}
	if s2.SeqFirst != 3 || s2.SeqLast != 4 {
		t.Fatalf("segment 2 range: %+v", s2)
	}
	if s2.TreeSize != 4 {
		t.Fatalf("second checkpoint tree size = %d, want 4 (append-only tree)", s2.TreeSize)
	}
	// The growing tree is consistent between the two checkpoints.
	all := [][32]byte{merkle.LeafHash([]byte("a")), merkle.LeafHash([]byte("b")),
		merkle.LeafHash([]byte("c")), merkle.LeafHash([]byte("d"))}
	proof := merkle.ConsistencyProof(all, 2, 4)
	if !merkle.VerifyConsistency(2, 4, proof, s1.Root, s2.Root) {
		t.Fatal("checkpoints are not append-only consistent")
	}
}

func TestSealEmptyFails(t *testing.T) {
	t.Parallel()
	b, _, _ := newBatcher(t)
	if _, err := b.Seal(time.Now()); err == nil {
		t.Fatal("sealing nothing should fail")
	}
}
