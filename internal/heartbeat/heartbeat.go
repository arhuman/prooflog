// Package heartbeat builds system.heartbeat records that prove a source was
// alive, observable, and able to log, carrying continuity counters, health
// metrics, and time-source metadata (REQ-E-06).
package heartbeat

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arhuman/prooflog/internal/envelope"
)

// EventType is the heartbeat event type.
const EventType = "system.heartbeat"

// TimeSource records how the agent's clock is synchronised, so reports can
// attest time-source trust (REQ-E-06).
type TimeSource struct {
	Source    string `json:"source"`           // e.g. "ntp", "nts", "none"
	SyncState string `json:"sync_state"`       // e.g. "synchronised", "unsynchronised"
	Server    string `json:"server,omitempty"` // time server, when known
}

// State is the sampled agent state embedded in a heartbeat payload (§6.3).
type State struct {
	Version         string
	UptimeSeconds   uint64
	LastLocalSeq    uint64
	LastUploadedSeq uint64
	LastAckSeq      uint64
	QueueDepth      uint64
	DiskFreeBytes   uint64
	ClockDriftMS    int64
	TimeSource      TimeSource
}

type agentBlock struct {
	Version       string `json:"version"`
	UptimeSeconds uint64 `json:"uptime_seconds"`
}

type continuityBlock struct {
	LastLocalSeq    uint64 `json:"last_local_seq"`
	LastUploadedSeq uint64 `json:"last_uploaded_seq"`
	LastAckSeq      uint64 `json:"last_ack_seq"`
	QueueDepth      uint64 `json:"queue_depth"`
}

type healthBlock struct {
	DiskFreeBytes uint64 `json:"disk_free_bytes"`
	ClockDriftMS  int64  `json:"clock_drift_ms"`
}

type payload struct {
	Agent      agentBlock      `json:"agent"`
	Continuity continuityBlock `json:"continuity"`
	Health     healthBlock     `json:"health"`
	TimeSource TimeSource      `json:"time_source"`
}

// Build assembles and serializes a heartbeat record for sourceID at seq,
// chained to prevHash, stamped at now (REQ-E-06). The payload is carried in
// clear (payload_clear) so the verifier can read it without decryption.
func Build(sourceID string, seq uint64, prevHash string, now time.Time, s State) (envelope.Record, error) {
	p := payload{
		Agent:      agentBlock{Version: s.Version, UptimeSeconds: s.UptimeSeconds},
		Continuity: continuityBlock{s.LastLocalSeq, s.LastUploadedSeq, s.LastAckSeq, s.QueueDepth},
		Health:     healthBlock{DiskFreeBytes: s.DiskFreeBytes, ClockDriftMS: s.ClockDriftMS},
		TimeSource: s.TimeSource,
	}
	clearJSON, err := json.Marshal(p)
	if err != nil {
		return envelope.Record{}, fmt.Errorf("heartbeat: marshal payload: %w", err)
	}
	ts := envelope.FormatTime(now)
	rec := envelope.Record{
		Version:      envelope.Version,
		SourceID:     sourceID,
		Seq:          seq,
		EventType:    EventType,
		EventTime:    ts,
		IngestTime:   ts,
		PayloadClear: clearJSON,
		PrevHash:     prevHash,
	}
	if err := rec.Serialize(); err != nil {
		return envelope.Record{}, err
	}
	return rec, nil
}

// Next supplies the sequence number and prev_hash for the next heartbeat.
type Next func() (seq uint64, prevHash string)

// Producer emits heartbeats on an injected tick channel (REQ-E-06). The clock
// is injected via the tick source, keeping it deterministic for tests.
type Producer struct {
	SourceID string
	Sample   func() State
	Next     Next
	Emit     func(envelope.Record) error
	Now      func() time.Time
}

// Run emits one heartbeat per received tick until ctx is done or a tick channel
// close. It returns ctx.Err() on cancellation.
func (p *Producer) Run(ctx context.Context, ticks <-chan time.Time) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-ticks:
			if !ok {
				return nil
			}
			seq, prev := p.Next()
			rec, err := Build(p.SourceID, seq, prev, p.Now(), p.Sample())
			if err != nil {
				return err
			}
			if err := p.Emit(rec); err != nil {
				return err
			}
		}
	}
}
