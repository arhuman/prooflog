package assess

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// BenchmarkReadLimited pins the memory-bounded read path (allocations tracked):
// ~50k synthetic JSONL lines under the generic profile, built once outside the
// timed loop.
func BenchmarkReadLimited(b *testing.B) {
	p, err := LoadProfile("generic")
	if err != nil {
		b.Fatalf("LoadProfile: %v", err)
	}
	var sb strings.Builder
	for i := 1; i <= 50_000; i++ {
		fmt.Fprintf(&sb, `{"source":"s","time":"2026-01-01T00:00:00Z","seq":%d,"type":"deploy","actor":"svc"}`+"\n", i)
	}
	input := []byte(sb.String())

	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for b.Loop() {
		if _, err := ReadLimited(p, Limits{}, bytes.NewReader(input)); err != nil {
			b.Fatalf("ReadLimited: %v", err)
		}
	}
}
