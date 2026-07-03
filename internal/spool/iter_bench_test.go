package spool

import (
	"bytes"
	"testing"
)

// BenchmarkIterNearTail fills the spool with many sealed segments, then iterates
// from a seq inside the last segment. With the leading-segment skip, cost is
// bounded by one boundary segment rather than the whole spool history, so the
// per-op time should stay flat as the spool grows (REQ-E-04).
func BenchmarkIterNearTail(b *testing.B) {
	payload := make([]byte, 0, 462)
	payload = append(payload, `{"data":"`...)
	payload = append(payload, bytes.Repeat([]byte("x"), 450)...)
	payload = append(payload, `"}`...)

	const (
		segments       = 128
		recsPerSegment = 32
		total          = segments * recsPerSegment
	)

	s, err := Open(Config{Dir: b.TempDir()})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	seq := uint64(0)
	for seg := 0; seg < segments; seg++ {
		for i := 0; i < recsPerSegment; i++ {
			seq++
			if err := s.Append(makeRecBench(b, seq, payload)); err != nil {
				b.Fatal(err)
			}
		}
		// Seal the segment so its max seq is cached in maxSeqByFile.
		if err := s.Roll(); err != nil {
			b.Fatal(err)
		}
	}

	// Replay from a watermark inside the final sealed segment: everything before
	// it should be skipped without a single parse or hash.
	fromSeq := uint64(total - recsPerSegment/2)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		it, err := s.Iter(fromSeq)
		if err != nil {
			b.Fatal(err)
		}
		count := 0
		for {
			_, ok, err := it.Next()
			if err != nil {
				b.Fatal(err)
			}
			if !ok {
				break
			}
			count++
		}
		if err := it.Close(); err != nil {
			b.Fatal(err)
		}
		if want := int(uint64(total) - fromSeq + 1); count != want {
			b.Fatalf("drained %d records, want %d", count, want)
		}
	}
}
