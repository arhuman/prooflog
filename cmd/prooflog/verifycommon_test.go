package main

import (
	"context"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/spool"
)

func TestParsePeriod(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"empty", "", false},
		{"valid", "2026-06-30:2026-07-03", false},
		{"missing sep", "2026-06-30", true},
		{"bad start", "nope:2026-07-03", true},
		{"bad end", "2026-06-30:nope", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := parsePeriod(tt.in)
			if tt.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.in == "2026-06-30:2026-07-03" && (start.IsZero() || end.IsZero()) {
				t.Fatal("valid period should parse both bounds")
			}
		})
	}
}

func TestGatherResultFromSpool(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(spool.Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	prev := envelope.ZeroHash
	for i := uint64(1); i <= 3; i++ {
		ts := envelope.FormatTime(time.Date(2026, 7, 3, int(i), 0, 0, 0, time.UTC))
		rec := envelope.Record{
			Version: envelope.Version, SourceID: "vps-01/api", Seq: i,
			EventType: "system.heartbeat", EventTime: ts, IngestTime: ts,
			PayloadClear: []byte(`{}`), PrevHash: prev,
		}
		if err := rec.Serialize(); err != nil {
			t.Fatal(err)
		}
		if err := sp.Append(rec); err != nil {
			t.Fatal(err)
		}
		prev = rec.HashHex()
	}
	_ = sp.Close()

	res, sourceID, err := gatherResult(context.Background(), verifyOpts{spoolDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if sourceID != "vps-01/api" {
		t.Fatalf("source id = %q, want vps-01/api", sourceID)
	}
	if !res.Chain.Valid || res.SeqLast != 3 {
		t.Fatalf("unexpected result: chainValid=%v seqLast=%d", res.Chain.Valid, res.SeqLast)
	}
}

func TestGatherResultNoSourceErrors(t *testing.T) {
	if _, _, err := gatherResult(context.Background(), verifyOpts{}); err == nil {
		t.Fatal("expected error when neither --spool nor --store-addr is set")
	}
}
