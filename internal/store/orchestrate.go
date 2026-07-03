package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// eventPostTimeout bounds a single event-sealing POST to the designated agent.
const eventPostTimeout = 5 * time.Second

// maxEventRespBytes caps the drained response body of an event POST.
const maxEventRespBytes = 1 << 20

// NewAgentEventSink returns an EventSink that seals store-originated system
// events by POSTing {"event_type", "payload_json"} as JSON to the designated
// agent's /v1/events HTTP ingest. When agentHTTP is empty it logs a warning and
// drops the event — the action still takes effect, only the event is not
// chain-sealed (WS6 settled decision).
func NewAgentEventSink(agentHTTP string, log *slog.Logger) EventSink {
	return func(ctx context.Context, eventType string, payload any) {
		if agentHTTP == "" {
			log.Warn("system event not chain-sealed (no --agent-http)", "event", eventType)
			return
		}
		if err := postEvent(ctx, agentHTTP, eventType, payload); err != nil {
			log.Warn("seal system event failed", "event", eventType, "agent", agentHTTP, "err", err)
		}
	}
}

// postEvent POSTs a single system event to the agent's /v1/events endpoint using
// a dedicated client with an explicit timeout, treating any non-2xx status as an
// error (lang-go client rules).
func postEvent(ctx context.Context, agentHTTP, eventType string, payload any) error {
	buf, err := json.Marshal(map[string]any{"event_type": eventType, "payload_json": payload})
	if err != nil {
		return fmt.Errorf("store: marshal event: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+agentHTTP+"/v1/events", bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("store: build event request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: eventPostTimeout}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return fmt.Errorf("store: post event: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, &io.LimitedReader{R: resp.Body, N: maxEventRespBytes})
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("store: agent returned %s", resp.Status)
	}
	return nil
}

// RunRetention records any retention-policy change, then enforces retention once
// at startup and on a ticker every interval, sealing a system event after any
// pass that produced tombstones. It blocks until ctx is cancelled; callers
// invoke it with `go`. interval <= 0 runs only the startup pass and returns.
// ApplyPolicy and enforcement errors are logged and never stop the loop
// (REQ-E-11, REQ-R-10).
func (s *Store) RunRetention(ctx context.Context, interval time.Duration) {
	if changed, oldJSON, newJSON, err := s.ApplyPolicy(ctx); err != nil {
		s.log.Error("apply retention policy", "err", err)
	} else if changed {
		sum := sha256.Sum256([]byte(newJSON))
		s.emitEvent(ctx, "system.retention_policy_changed", policyChangePayload(oldJSON, newJSON, hex.EncodeToString(sum[:])))
	}

	enforce := func() {
		tombstones, err := s.EnforceRetention(ctx)
		if err != nil {
			s.log.Error("enforce retention", "err", err)
			return
		}
		if len(tombstones) > 0 {
			s.emitEvent(ctx, "system.retention_deleted", tombstonePayload(tombstones))
		}
	}
	enforce()
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			enforce()
		}
	}
}

// policyChangePayload builds the system.retention_policy_changed payload: the
// prior policy JSON (null when none), the new policy JSON, and its SHA-256.
func policyChangePayload(oldJSON, newJSON, sha string) map[string]any {
	var old any
	if oldJSON != "" {
		old = json.RawMessage(oldJSON)
	}
	return map[string]any{
		"old_policy": old,
		"new_policy": json.RawMessage(newJSON),
		"sha256":     sha,
	}
}

// tombstonePayload renders the system.retention_deleted payload: one entry per
// deleted segment with its seq range, hex root, and the policy JSON.
func tombstonePayload(tombstones []Tombstone) map[string]any {
	list := make([]map[string]any, 0, len(tombstones))
	for _, t := range tombstones {
		list = append(list, map[string]any{
			"segment_id": t.SegmentID,
			"source_id":  t.SourceID,
			"seq_first":  t.SeqFirst,
			"seq_last":   t.SeqLast,
			"root":       hex.EncodeToString(t.Root),
			"policy":     json.RawMessage(t.Policy),
		})
	}
	return map[string]any{"deleted": list}
}
