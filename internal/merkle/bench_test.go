package merkle

import "testing"

func BenchmarkRoot(b *testing.B) {
	for _, tc := range []struct {
		name string
		n    int
	}{
		{"1_000", 1_000},
		{"10_000", 10_000},
		{"100_000", 100_000},
	} {
		leaves := makeLeaves(tc.n)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Root(leaves)
			}
		})
	}
}

func BenchmarkVerifyInclusion(b *testing.B) {
	const n = 10_000
	leaves := makeLeaves(n)
	root := Root(leaves)
	proof := InclusionProof(leaves, n/2)
	leaf := leaves[n/2]
	b.ReportAllocs()
	for b.Loop() {
		VerifyInclusion(leaf, n/2, n, proof, root)
	}
}

func BenchmarkConsistencyProof(b *testing.B) {
	const n = 10_000
	leaves := makeLeaves(n)
	b.ReportAllocs()
	for b.Loop() {
		ConsistencyProof(leaves, n/2, n)
	}
}
