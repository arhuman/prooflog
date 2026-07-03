package chain

import (
	"testing"

	"github.com/arhuman/prooflog/internal/envelope"
)

func buildChainBench(b *testing.B, n int) []Entry {
	b.Helper()
	entries := make([]Entry, 0, n)
	prev := Genesis
	for i := 1; i <= n; i++ {
		r := envelope.Record{
			Version:      envelope.Version,
			SourceID:     "vps-01/api",
			Seq:          uint64(i),
			EventType:    "system.heartbeat",
			EventTime:    "2026-07-03T12:00:00.000000000Z",
			IngestTime:   "2026-07-03T12:00:00.000000000Z",
			PrevHash:     prev,
			PayloadClear: []byte(`{"i":` + itoa(i) + `}`),
		}
		if err := r.Serialize(); err != nil {
			b.Fatal(err)
		}
		entries = append(entries, Entry{Bytes: r.Bytes(), Hash: r.HashHex()})
		prev = r.HashHex()
	}
	return entries
}

func BenchmarkVerify(b *testing.B) {
	for _, tc := range []struct {
		name string
		n    int
	}{
		{"1_000", 1_000},
		{"10_000", 10_000},
	} {
		entries := buildChainBench(b, tc.n)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := Verify(entries); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
