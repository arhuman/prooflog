// Package envelope defines the Record, the unit of evidence, its pinned
// single-line JSON serialization, and SHA-256 hashing (REQ-C-04, REQ-C-13,
// REQ-E-07).
package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Version is the current record schema version. v2 (BREAKING, pre-alpha) made
// actor a per-subject HMAC pseudonym and removed the plaintext labels field:
// labels now travel inside the encrypted payload. Records written under v1 are
// rejected — there is no dual-version support.
const Version = 2

// ValidOutcomes is the closed set of accepted outcome values (REQ-E-07,
// FAU_GEN.1). The empty string means "unknown/unspecified". It is exported so
// the agent and HTTP layers can reuse it in their rejection messages.
var ValidOutcomes = map[string]bool{
	"":        true,
	"success": true,
	"failure": true,
	"denied":  true,
	"unknown": true,
}

// ZeroHash is the genesis prev_hash: 64 zero hex characters.
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// TimeFormat pins one exact RFC 3339 byte layout for hashed timestamps:
// UTC only, uppercase T, 9-digit nanoseconds, uppercase Z (REQ-C-13).
const timeLayout = "2006-01-02T15:04:05.000000000"

// FormatTime renders t in the pinned RFC 3339 UTC format (REQ-C-13).
func FormatTime(t time.Time) string {
	return t.UTC().Format(timeLayout) + "Z"
}

// ParseTime parses a timestamp in the pinned RFC 3339 UTC format (REQ-C-13).
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout+"Z", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("envelope: parse time %q: %w", s, err)
	}
	return t.UTC(), nil
}

// Record is the unit of evidence. It is serialized ONCE at acceptance to a
// single-line JSON with fixed field order (struct order); those exact bytes
// are hashed, stored, uploaded, and verified — never re-serialized (REQ-C-04).
// It also carries date/time, event type, subject identity, and outcome, the
// FAU_GEN.1 minimum (REQ-E-07).
type Record struct {
	Version    int    `json:"v"`
	SourceID   string `json:"source_id"`
	Seq        uint64 `json:"seq"`
	EventType  string `json:"event_type"`
	EventTime  string `json:"event_time"`
	IngestTime string `json:"ingest_time"`
	// Actor is a 64-hex HMAC pseudonym for the acting subject (v2), or empty
	// (system events, or unknown). The salt that re-links it to an identity
	// lives only on the source host and is erasable (GDPR Art. 17).
	Actor        string          `json:"actor"`
	Outcome      string          `json:"outcome"`
	PayloadClear json.RawMessage `json:"payload_clear,omitempty"`
	PayloadCT    string          `json:"payload_ct,omitempty"`
	PayloadHash  string          `json:"payload_hash,omitempty"`
	KeyID        string          `json:"key_id,omitempty"`
	PrevHash     string          `json:"prev_hash"`

	raw  []byte
	hash [32]byte
}

// Serialize pins the record's canonical single-line JSON bytes and computes
// their SHA-256, storing both. It must be called once at acceptance; the
// stored bytes are the canonical form and are never regenerated (REQ-C-04).
func (r *Record) Serialize() error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("envelope: serialize: %w", err)
	}
	r.raw = bytes.TrimRight(buf.Bytes(), "\n")
	r.hash = sha256.Sum256(r.raw)
	return nil
}

// Parse reconstructs a Record from its stored bytes, keeping those exact bytes
// as canonical and recomputing their hash — it never re-serializes (REQ-C-04).
func Parse(b []byte) (Record, error) {
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return Record{}, fmt.Errorf("envelope: parse: %w", err)
	}
	r.raw = append([]byte(nil), b...)
	r.hash = sha256.Sum256(r.raw)
	return r, nil
}

// Bytes returns the pinned canonical bytes. Nil until Serialize or Parse.
func (r Record) Bytes() []byte { return r.raw }

// Hash returns the SHA-256 of the canonical bytes.
func (r Record) Hash() [32]byte { return r.hash }

// HashHex returns the lowercase hex SHA-256 of the canonical bytes.
func (r Record) HashHex() string { return hex.EncodeToString(r.hash[:]) }

// IsSystem reports whether the record is a system event (system.*), which
// carries payload_clear instead of encrypted payload_ct.
func (r Record) IsSystem() bool { return strings.HasPrefix(r.EventType, "system.") }

var (
	// ErrMissingField signals an absent mandatory field.
	ErrMissingField = errors.New("envelope: missing required field")
	// ErrPayloadShape signals a payload/event-type mismatch.
	ErrPayloadShape = errors.New("envelope: invalid payload shape")
	// ErrBadHash signals a malformed hex hash field.
	ErrBadHash = errors.New("envelope: malformed hash")
	// ErrBadActor signals an actor that is not a valid 64-hex pseudonym.
	ErrBadActor = errors.New("envelope: invalid actor pseudonym")
	// ErrBadOutcome signals an outcome outside the closed enum.
	ErrBadOutcome = errors.New("envelope: invalid outcome")
)

// Validate checks required fields and the payload shape: system.* events carry
// payload_clear; all others carry payload_ct + payload_hash (REQ-E-07).
func (r Record) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("%w: v", ErrMissingField)
	}
	if r.SourceID == "" {
		return fmt.Errorf("%w: source_id", ErrMissingField)
	}
	if r.Seq == 0 {
		return fmt.Errorf("%w: seq", ErrMissingField)
	}
	if r.EventType == "" {
		return fmt.Errorf("%w: event_type", ErrMissingField)
	}
	if r.EventTime == "" {
		return fmt.Errorf("%w: event_time", ErrMissingField)
	}
	if r.IngestTime == "" {
		return fmt.Errorf("%w: ingest_time", ErrMissingField)
	}
	if !isHex(r.PrevHash, 64) {
		return fmt.Errorf("%w: prev_hash", ErrBadHash)
	}
	if !ValidOutcomes[r.Outcome] {
		return fmt.Errorf("%w: outcome %q", ErrBadOutcome, r.Outcome)
	}
	// A non-system actor, when present, must be a 64-lowercase-hex pseudonym.
	if !r.IsSystem() && r.Actor != "" && !isLowerHex(r.Actor, 64) {
		return fmt.Errorf("%w: actor must be a 64-hex pseudonym", ErrBadActor)
	}
	if r.IsSystem() {
		if len(r.PayloadClear) == 0 {
			return fmt.Errorf("%w: system event needs payload_clear", ErrPayloadShape)
		}
		if r.PayloadCT != "" || r.PayloadHash != "" {
			return fmt.Errorf("%w: system event must not carry payload_ct", ErrPayloadShape)
		}
		return nil
	}
	if len(r.PayloadClear) != 0 {
		return fmt.Errorf("%w: non-system event must not carry payload_clear", ErrPayloadShape)
	}
	if r.PayloadCT == "" {
		return fmt.Errorf("%w: payload_ct", ErrMissingField)
	}
	if !isHex(r.PayloadHash, 64) {
		return fmt.Errorf("%w: payload_hash", ErrBadHash)
	}
	if r.KeyID == "" {
		return fmt.Errorf("%w: key_id", ErrMissingField)
	}
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// isLowerHex reports whether s is exactly n lowercase hex characters. Actor
// pseudonyms are emitted lowercase; uppercase hex is rejected to keep the
// hashed bytes canonical.
func isLowerHex(s string, n int) bool {
	if !isHex(s, n) {
		return false
	}
	return !strings.ContainsAny(s, "ABCDEF")
}
