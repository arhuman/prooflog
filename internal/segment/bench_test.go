package segment

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func BenchmarkBatcherSeal(b *testing.B) {
	now := time.Now()
	for _, tc := range []struct {
		name  string
		count int
	}{
		{"100", 100},
		{"1_000", 1_000},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				bt := New("prooflog/acme/vps-01/api", "vps-01-api", priv,
					WithMaxRecords(tc.count+1), WithMaxAge(time.Hour))
				for j := 1; j <= tc.count; j++ {
					if err := bt.Add([]byte("record"), uint64(j), now); err != nil {
						b.Fatal(err)
					}
				}
				b.StartTimer()
				if _, err := bt.Seal(now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkBatcherSealLargeTree isolates the per-seal cost over a large restored
// tree. With the incremental merkle.Hasher a single Seal is O(log n) regardless
// of tree size, so restoring 100k (or 1M) leaves before measuring one Seal keeps
// the seal cost flat where the naive recursive recompute grew O(n) (REQ-C-01).
func BenchmarkBatcherSealLargeTree(b *testing.B) {
	now := time.Now()
	for _, tc := range []struct {
		name  string
		count int
	}{
		{"100_000", 100_000},
		{"1_000_000", 1_000_000},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				bt := New("prooflog/acme/vps-01/api", "vps-01-api", priv,
					WithMaxRecords(tc.count+1), WithMaxAge(time.Hour))
				for j := 0; j < tc.count; j++ {
					bt.Restore([]byte("record"))
				}
				if err := bt.Add([]byte("record"), uint64(tc.count)+1, now); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if _, err := bt.Seal(now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
