package merkle

import (
	"crypto/sha256"
	"math/rand"
	"testing"
)

// TestHasherMatchesRoot machine-checks the Hasher against the recursive RFC 6962
// reference Root at every prefix, so the incremental construction is proven
// equivalent, never assumed (REQ-C-01, REQ-C-02).
func TestHasherMatchesRoot(t *testing.T) {
	t.Parallel()
	// Empty tree: Root() with no Add must equal SHA-256("").
	var empty Hasher
	if got, want := empty.Root(), sha256.Sum256(nil); got != want {
		t.Fatalf("empty Hasher root = %x, want %x", got, want)
	}

	// Exhaustive small range: assert the prefix root after each Add matches
	// Root(leaves[:k]) for every k in 0..257 (covers all powers of two ±1).
	const maxN = 257
	leaves := makeLeaves(maxN)
	var h Hasher
	if got, want := h.Root(), Root(leaves[:0]); got != want {
		t.Fatalf("prefix 0: got %x, want %x", got, want)
	}
	for k := 1; k <= maxN; k++ {
		h.Add(leaves[k-1])
		if h.Size() != uint64(k) {
			t.Fatalf("prefix %d: Size = %d", k, h.Size())
		}
		if got, want := h.Root(), Root(leaves[:k]); got != want {
			t.Fatalf("prefix %d: got %x, want %x", k, got, want)
		}
	}

	// A few larger random sizes: only the final root is checked.
	rng := rand.New(rand.NewSource(0x50f7))
	for range 8 {
		n := 1 + rng.Intn(10000)
		big := makeLeaves(n)
		var hb Hasher
		for _, leaf := range big {
			hb.Add(leaf)
		}
		if got, want := hb.Root(), Root(big); got != want {
			t.Fatalf("random size %d: got %x, want %x", n, got, want)
		}
	}
}

// BenchmarkPrefixRoots compares the old per-checkpoint pattern (a full recursive
// Root(leaves[:s]) recompute for each of 50 sizes) against the single-sweep
// incremental Hasher producing the same 50 prefix roots.
func BenchmarkPrefixRoots(b *testing.B) {
	const total = 100_000
	const snaps = 50
	leaves := makeLeaves(total)
	sizes := make([]int, snaps)
	for i := range sizes {
		sizes[i] = (i + 1) * total / snaps
	}

	b.Run("recursive", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, s := range sizes {
				_ = Root(leaves[:s])
			}
		}
	})

	b.Run("hasher", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var h Hasher
			pos := 0
			for _, s := range sizes {
				for pos < s {
					h.Add(leaves[pos])
					pos++
				}
				_ = h.Root()
			}
		}
	})
}
