package store

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// ---- tombstonePayload -------------------------------------------------------

// TestTombstonePayload verifies that tombstonePayload renders all tombstone
// fields correctly into the event payload map.
func TestTombstonePayload(t *testing.T) {
	root := make([]byte, 32)
	root[0] = 0xab
	tombstones := []Tombstone{
		{
			SegmentID: "seg-001",
			SourceID:  "vps-01/api",
			SeqFirst:  1,
			SeqLast:   256,
			Root:      root,
			DeletedAt: time.Now(),
		},
	}

	payload := tombstonePayload(tombstones)
	deleted, ok := payload["deleted"].([]map[string]any)
	if !ok {
		t.Fatalf("deleted not a []map[string]any: %T", payload["deleted"])
	}
	if len(deleted) != 1 {
		t.Fatalf("len(deleted) = %d, want 1", len(deleted))
	}
	entry := deleted[0]
	if entry["segment_id"] != "seg-001" {
		t.Errorf("segment_id = %v, want seg-001", entry["segment_id"])
	}
	if entry["source_id"] != "vps-01/api" {
		t.Errorf("source_id = %v, want vps-01/api", entry["source_id"])
	}
	if entry["seq_first"] != uint64(1) {
		t.Errorf("seq_first = %v, want 1", entry["seq_first"])
	}
	if entry["seq_last"] != uint64(256) {
		t.Errorf("seq_last = %v, want 256", entry["seq_last"])
	}
}

// TestTombstonePayloadEmpty ensures an empty tombstone list produces a
// non-nil "deleted" key with an empty slice.
func TestTombstonePayloadEmpty(t *testing.T) {
	payload := tombstonePayload(nil)
	deleted, ok := payload["deleted"]
	if !ok {
		t.Fatal("missing 'deleted' key")
	}
	list, ok := deleted.([]map[string]any)
	if !ok {
		t.Fatalf("deleted not []map[string]any: %T", deleted)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d entries", len(list))
	}
}

// ---- policyChangePayload ----------------------------------------------------

// TestPolicyChangePayloadWithOld exercises the path where both an old and a
// new policy JSON are given.
func TestPolicyChangePayloadWithOld(t *testing.T) {
	oldJSON := `{"default_days":30}`
	newJSON := `{"default_days":90}`
	sha := "abcdef1234567890"

	payload := policyChangePayload(oldJSON, newJSON, sha)
	if payload["sha256"] != sha {
		t.Errorf("sha256 = %v, want %q", payload["sha256"], sha)
	}
	if payload["old_policy"] == nil {
		t.Error("old_policy should be non-nil when old JSON is provided")
	}
}

// TestPolicyChangePayloadNoOld exercises the path where there is no prior
// policy (old_policy must be nil).
func TestPolicyChangePayloadNoOld(t *testing.T) {
	payload := policyChangePayload("", `{"default_days":90}`, "sha256hex")
	if payload["old_policy"] != nil {
		t.Errorf("old_policy should be nil when oldJSON is empty, got %v", payload["old_policy"])
	}
}

// ---- NewAgentEventSink ------------------------------------------------------

// TestNewAgentEventSinkNoHTTP ensures that a sink with no --agent-http
// configured does not panic and drops the event gracefully (no POST attempted).
func TestNewAgentEventSinkNoHTTP(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sink := NewAgentEventSink("", log)
	// Must not panic and must not attempt a POST (empty addr short-circuits).
	sink(t.Context(), "system.test", map[string]any{"key": "value"})
}

// ---- RunRetention -----------------------------------------------------------

// TestRunRetentionStartupPass runs a single startup pass (interval <= 0) over a
// store with a freshly applied policy and one expired segment, asserting it
// returns, tombstones the segment, and emits the policy-changed then
// retention-deleted events in order.
func TestRunRetentionStartupPass(t *testing.T) {
	s := newTestStore(t)
	s.policy = RetentionPolicy{DefaultDays: 30}
	blob := seedSegment(t, s, "seg-old", "vps-01/api", 1, 10, time.Now().AddDate(0, 0, -40))

	var events []string
	s.SetEventSink(func(_ context.Context, eventType string, _ any) {
		events = append(events, eventType)
	})

	s.RunRetention(context.Background(), 0)

	if !fileGone(blob) {
		t.Fatal("expired blob should be removed")
	}
	want := []string{"system.retention_policy_changed", "system.retention_deleted"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i, e := range want {
		if events[i] != e {
			t.Errorf("events[%d] = %q, want %q", i, events[i], e)
		}
	}
}
