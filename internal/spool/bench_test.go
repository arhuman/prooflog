package spool

import (
	"bytes"
	"testing"

	"github.com/arhuman/prooflog/internal/envelope"
)

func makeRecBench(b *testing.B, seq uint64, payload []byte) envelope.Record {
	b.Helper()
	r := envelope.Record{
		Version:      envelope.Version,
		SourceID:     "vps-01/api",
		Seq:          seq,
		EventType:    "system.heartbeat",
		EventTime:    "2026-07-03T12:00:00.000000000Z",
		IngestTime:   "2026-07-03T12:00:00.000000000Z",
		PayloadClear: payload,
		PrevHash:     envelope.ZeroHash,
	}
	if err := r.Serialize(); err != nil {
		b.Fatal(err)
	}
	return r
}

func BenchmarkSpoolAppend(b *testing.B) {
	payload := make([]byte, 0, 462)
	payload = append(payload, `{"data":"`...)
	payload = append(payload, bytes.Repeat([]byte("x"), 450)...)
	payload = append(payload, `"}`...)

	dir := b.TempDir()
	s, err := Open(Config{Dir: dir})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	recs := make([]envelope.Record, b.N)
	for i := range recs {
		recs[i] = makeRecBench(b, uint64(i+1), payload)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.Append(recs[i]); err != nil {
			b.Fatal(err)
		}
	}
}
