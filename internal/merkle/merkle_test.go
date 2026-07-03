package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Independently citable RFC 6962 known-answer vectors.
const (
	emptyRootHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA-256("")
	leafEmptyHex = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" // SHA-256(0x00)
)

func hexOf(h [32]byte) string { return hex.EncodeToString(h[:]) }

func TestLeafHashKnownAnswer(t *testing.T) {
	t.Parallel()
	if got := hexOf(LeafHash(nil)); got != leafEmptyHex {
		t.Fatalf("LeafHash(empty) = %s, want %s", got, leafEmptyHex)
	}
}

func TestRootKnownAnswers(t *testing.T) {
	t.Parallel()
	if got := hexOf(Root(nil)); got != emptyRootHex {
		t.Fatalf("empty Root = %s, want %s", got, emptyRootHex)
	}
	d0 := LeafHash([]byte("a"))
	if got := Root([][32]byte{d0}); got != d0 {
		t.Fatalf("single-leaf Root != leaf hash")
	}
	d1 := LeafHash([]byte("b"))
	want := nodeHash(d0, d1)
	if got := Root([][32]byte{d0, d1}); got != want {
		t.Fatalf("two-leaf Root = %s, want %s", hexOf(got), hexOf(want))
	}
}

func TestLargestPowerOfTwoLessThan(t *testing.T) {
	t.Parallel()
	tests := []struct{ n, want int }{
		{2, 1}, {3, 2}, {4, 2}, {5, 4}, {7, 4}, {8, 4}, {9, 8}, {16, 8}, {17, 16},
	}
	for _, tt := range tests {
		if got := largestPowerOfTwoLessThan(tt.n); got != tt.want {
			t.Errorf("largestPowerOfTwoLessThan(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}

func makeLeaves(n int) [][32]byte {
	leaves := make([][32]byte, n)
	for i := range leaves {
		leaves[i] = LeafHash([]byte{byte(i), byte(i >> 8), 0x55})
	}
	return leaves
}

func TestInclusionRoundTrip(t *testing.T) {
	t.Parallel()
	for n := 1; n <= 16; n++ {
		leaves := makeLeaves(n)
		root := Root(leaves)
		for m := 0; m < n; m++ {
			proof := InclusionProof(leaves, m)
			if !VerifyInclusion(leaves[m], m, n, proof, root) {
				t.Fatalf("inclusion failed n=%d m=%d", n, m)
			}
			// A tampered leaf must not verify.
			bad := leaves[m]
			bad[0] ^= 0xff
			if VerifyInclusion(bad, m, n, proof, root) {
				t.Fatalf("tampered inclusion verified n=%d m=%d", n, m)
			}
		}
	}
}

func TestInclusionRejectsWrongRoot(t *testing.T) {
	t.Parallel()
	leaves := makeLeaves(7)
	root := Root(leaves)
	root[0] ^= 0x01
	if VerifyInclusion(leaves[3], 3, 7, InclusionProof(leaves, 3), root) {
		t.Fatal("inclusion verified against wrong root")
	}
}

func TestConsistencyRoundTrip(t *testing.T) {
	t.Parallel()
	for n := 1; n <= 16; n++ {
		leaves := makeLeaves(n)
		newRoot := Root(leaves)
		for m := 1; m <= n; m++ {
			oldRoot := Root(leaves[:m])
			proof := ConsistencyProof(leaves, m, n)
			if !VerifyConsistency(m, n, proof, oldRoot, newRoot) {
				t.Fatalf("consistency failed m=%d n=%d", m, n)
			}
		}
	}
}

func TestConsistencyRejectsForkedRoot(t *testing.T) {
	t.Parallel()
	leaves := makeLeaves(9)
	newRoot := Root(leaves)
	oldRoot := Root(leaves[:4])
	proof := ConsistencyProof(leaves, 4, 9)
	forked := newRoot
	forked[5] ^= 0x80
	if VerifyConsistency(4, 9, proof, oldRoot, forked) {
		t.Fatal("consistency verified against forked new root")
	}
	badOld := oldRoot
	badOld[1] ^= 0x01
	if VerifyConsistency(4, 9, proof, badOld, newRoot) {
		t.Fatal("consistency verified against wrong old root")
	}
}

func TestRootFromEntriesMatchesLeafHashing(t *testing.T) {
	t.Parallel()
	entries := [][]byte{[]byte("x"), []byte("yy"), []byte("zzz")}
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = LeafHash(e)
	}
	if RootFromEntries(entries) != Root(leaves) {
		t.Fatal("RootFromEntries mismatch")
	}
}

func TestEmptyMatchesStdlib(t *testing.T) {
	t.Parallel()
	want := sha256.Sum256(nil)
	if Root(nil) != want {
		t.Fatal("empty root not SHA-256 of empty string")
	}
}
