package heartbeat

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/envelope"
)

func sampleState() State {
	return State{
		Version:         "0.1.0",
		UptimeSeconds:   86400,
		LastLocalSeq:    1842,
		LastUploadedSeq: 1839,
		LastAckSeq:      1839,
		QueueDepth:      4,
		DiskFreeBytes:   39120404480,
		ClockDriftMS:    42,
		TimeSource:      TimeSource{Source: "ntp", SyncState: "synchronised", Server: "pool.ntp.org"},
	}
}

func TestBuildProducesValidSystemRecord(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 3, 10, 2, 0, 0, time.UTC)
	rec, err := Build("vps-01/api", 1843, envelope.ZeroHash, now, sampleState())
	if err != nil {
		t.Fatal(err)
	}
	if rec.EventType != EventType {
		t.Fatalf("event type = %s", rec.EventType)
	}
	if !rec.IsSystem() {
		t.Fatal("heartbeat must be a system event")
	}
	if err := rec.Validate(); err != nil {
		t.Fatalf("heartbeat record invalid: %v", err)
	}
	if rec.EventTime != "2026-07-03T10:02:00.000000000Z" {
		t.Fatalf("event_time not pinned: %s", rec.EventTime)
	}
	if len(rec.Bytes()) == 0 || rec.HashHex() == "" {
		t.Fatal("record not serialized")
	}
}

func TestBuildPayloadContents(t *testing.T) {
	t.Parallel()
	now := time.Now()
	rec, err := Build("s", 2, envelope.ZeroHash, now, sampleState())
	if err != nil {
		t.Fatal(err)
	}
	var p payload
	if err := json.Unmarshal(rec.PayloadClear, &p); err != nil {
		t.Fatal(err)
	}
	if p.Continuity.LastLocalSeq != 1842 || p.Continuity.QueueDepth != 4 {
		t.Fatalf("continuity block wrong: %+v", p.Continuity)
	}
	if p.Health.DiskFreeBytes != 39120404480 || p.Health.ClockDriftMS != 42 {
		t.Fatalf("health block wrong: %+v", p.Health)
	}
	if p.Agent.Version != "0.1.0" || p.Agent.UptimeSeconds != 86400 {
		t.Fatalf("agent block wrong: %+v", p.Agent)
	}
	if p.TimeSource.Source != "ntp" || p.TimeSource.SyncState != "synchronised" {
		t.Fatalf("time source metadata missing: %+v", p.TimeSource)
	}
}

func TestProducerEmitsPerTick(t *testing.T) {
	t.Parallel()
	var seq uint64 = 100
	now := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	var emitted []envelope.Record
	p := &Producer{
		SourceID: "vps-01/api",
		Sample:   sampleState,
		Next: func() (uint64, string) {
			seq++
			return seq, envelope.ZeroHash
		},
		Emit: func(r envelope.Record) error { emitted = append(emitted, r); return nil },
		Now:  func() time.Time { return now },
	}
	ticks := make(chan time.Time, 3)
	for i := 0; i < 3; i++ {
		ticks <- now
	}
	close(ticks)
	if err := p.Run(context.Background(), ticks); err != nil {
		t.Fatal(err)
	}
	if len(emitted) != 3 {
		t.Fatalf("emitted %d heartbeats, want 3", len(emitted))
	}
	if emitted[0].Seq != 101 || emitted[2].Seq != 103 {
		t.Fatalf("seq assignment wrong: %d..%d", emitted[0].Seq, emitted[2].Seq)
	}
}

func TestProducerStopsOnContextCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &Producer{
		SourceID: "s",
		Sample:   sampleState,
		Next:     func() (uint64, string) { return 1, envelope.ZeroHash },
		Emit:     func(envelope.Record) error { return nil },
		Now:      time.Now,
	}
	ticks := make(chan time.Time)
	if err := p.Run(ctx, ticks); err == nil {
		t.Fatal("expected context error")
	}
}
