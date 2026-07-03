// Package client is the public Go SDK for sending application events to a local
// prooflog agent (REQ-E-04).
//
// Applications integrate by POSTing business events to the agent's ingest
// endpoint. That endpoint is loopback-only by design: the agent binds
// 127.0.0.1 and the client sends plaintext over HTTP to localhost. This is
// intentional and safe — the agent, not the client, performs the cryptographic
// work: it pseudonymizes the actor into an erasable HMAC and folds labels and
// payload into a client-side-encrypted blob before anything is hashed or
// uploaded. The plaintext you send never leaves the host in the clear.
//
// Privacy rule: event_type and source_id stay PLAINTEXT in the stored envelope.
// Never encode personal data, secrets, tokens, or emails into an event Type.
// Put subject identity in Actor (stored as a pseudonym) and any detail in the
// encrypted Payload or Labels. See docs/event-taxonomy.md and
// docs/threat-model.md.
//
// This package depends only on the standard library; importing it pulls in no
// internal prooflog packages.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Default ingest address and response bound.
const (
	defaultAddr    = "127.0.0.1:9600"
	defaultTimeout = 10 * time.Second
	maxRespBytes   = 1 << 20 // 1 MiB
)

// Outcome values accepted by the agent (REQ-E-07). The empty string means
// unknown/unspecified.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
	OutcomeUnknown = "unknown"
)

// v1 event-type taxonomy: a scoped starting set of common security-relevant
// events (see docs/event-taxonomy.md). Types follow a lowercase dotted
// domain.action convention. Extend with your own dotted types as needed.
//
// The system.* namespace is reserved for the agent and is deliberately absent
// here: applications must not forge system events, and Send rejects them.
const (
	EventDeployStarted   = "deploy.started"
	EventDeployCompleted = "deploy.completed"
	EventDeployFailed    = "deploy.failed"

	EventAccessGranted          = "access.granted"
	EventAccessRevoked          = "access.revoked"
	EventAccessPrivilegeChanged = "access.privilege_changed"

	EventSecretRotated = "secret.rotated"
	EventSecretExposed = "secret.exposed"
	EventSecretRevoked = "secret.revoked"

	EventBackupCompleted     = "backup.completed"
	EventBackupRestoreTested = "backup.restore_tested"
	EventBackupFailed        = "backup.failed"

	EventIncidentDetected = "incident.detected"
	EventIncidentTriaged  = "incident.triaged"
	EventIncidentReported = "incident.reported"
	EventIncidentResolved = "incident.resolved"

	EventDataExported            = "data.exported"
	EventDataDeleted             = "data.deleted"
	EventDataRetentionHoldPlaced = "data.retention_hold_placed"
)

// validOutcomes is the closed set accepted client-side (mirrors
// envelope.ValidOutcomes without importing internal).
var validOutcomes = map[string]bool{
	"":             true,
	OutcomeSuccess: true,
	OutcomeFailure: true,
	OutcomeDenied:  true,
	OutcomeUnknown: true,
}

// Event is one application event to record. Type is required; the remaining
// fields are optional.
type Event struct {
	// Type is the taxonomy event type (e.g. EventAccessRevoked). Required.
	// Must not be a system.* type.
	Type string
	// Actor is the acting subject identity in plaintext; the agent replaces it
	// with an erasable HMAC pseudonym before hashing.
	Actor string
	// Outcome is one of the Outcome* constants or empty (unknown).
	Outcome string
	// Labels are folded into the encrypted payload by the agent.
	Labels map[string]string
	// Payload is JSON-marshaled into payload_json. A struct or map is marshaled;
	// a json.RawMessage or []byte is passed through after a validity check; nil
	// is omitted. It is encrypted by the agent.
	Payload any
	// Time is the event timestamp. Zero lets the agent stamp acceptance time.
	Time time.Time
}

// Accepted is the agent's acknowledgement that a record was durably accepted.
type Accepted struct {
	Seq        uint64
	RecordHash string
	EventType  string
}

// APIError is returned when the agent responds with a non-200 status. Message
// carries the agent's {error} body when present.
type APIError struct {
	StatusCode int
	Message    string
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("prooflog agent returned %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("prooflog agent returned %d", e.StatusCode)
}

// eventRequest is the POST /v1/events JSON body. Defined here so external
// importers do not pull in internal packages.
type eventRequest struct {
	EventType string            `json:"event_type"`
	EventTime string            `json:"event_time,omitempty"`
	Actor     string            `json:"actor,omitempty"`
	Outcome   string            `json:"outcome,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Payload   json.RawMessage   `json:"payload_json,omitempty"`
}

// acceptResponse is the 200 body.
type acceptResponse struct {
	Seq        uint64 `json:"seq"`
	RecordHash string `json:"record_hash"`
	EventType  string `json:"event_type"`
}

// errorResponse is the non-200 body.
type errorResponse struct {
	Error string `json:"error"`
}

// Client sends events to a local prooflog agent's ingest endpoint.
type Client struct {
	baseURL string
	http    *http.Client
}

// Option configures a Client.
type Option func(*config)

type config struct {
	http    *http.Client
	timeout time.Duration
}

// WithHTTPClient sets a custom HTTP client. When set, it is used as-is and
// WithTimeout is ignored.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *config) { c.http = hc }
}

// WithTimeout sets the per-request timeout of the default HTTP client
// (default 10s). Ignored when WithHTTPClient is supplied.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// New builds a Client for the agent ingest address host:port. An empty addr
// defaults to 127.0.0.1:9600. The base URL is http://<addr>: ingest is
// loopback plaintext by design (REQ-E-04).
func New(addr string, opts ...Option) *Client {
	if addr == "" {
		addr = defaultAddr
	}
	cfg := config{timeout: defaultTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}
	hc := cfg.http
	if hc == nil {
		hc = &http.Client{Timeout: cfg.timeout}
	}
	return &Client{baseURL: "http://" + addr, http: hc}
}

// Send validates e, POSTs it to /v1/events, and returns the agent's
// acknowledgement. A non-200 response yields an *APIError.
func (c *Client) Send(ctx context.Context, e Event) (Accepted, error) {
	if e.Type == "" {
		return Accepted{}, errors.New("client: Event.Type is required")
	}
	if strings.HasPrefix(e.Type, "system.") {
		return Accepted{}, fmt.Errorf("client: event type %q is reserved for the agent; applications must not send system.* events", e.Type)
	}
	if !validOutcomes[e.Outcome] {
		return Accepted{}, fmt.Errorf("client: invalid outcome %q; must be empty or one of success, failure, denied, unknown", e.Outcome)
	}
	payload, err := encodePayload(e.Payload)
	if err != nil {
		return Accepted{}, err
	}

	body := eventRequest{
		EventType: e.Type,
		Actor:     e.Actor,
		Outcome:   e.Outcome,
		Labels:    e.Labels,
		Payload:   payload,
	}
	if !e.Time.IsZero() {
		body.EventTime = e.Time.UTC().Format(time.RFC3339Nano)
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return Accepted{}, fmt.Errorf("client: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/events", bytes.NewReader(buf))
	if err != nil {
		return Accepted{}, fmt.Errorf("client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Accepted{}, fmt.Errorf("client: send request: %w", err)
	}
	defer resp.Body.Close()

	limited := &io.LimitedReader{R: resp.Body, N: maxRespBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return Accepted{}, fmt.Errorf("client: read response: %w", err)
	}
	if limited.N == 0 {
		return Accepted{}, fmt.Errorf("client: response exceeds %d bytes", maxRespBytes)
	}

	if resp.StatusCode != http.StatusOK {
		var er errorResponse
		_ = json.Unmarshal(data, &er)
		return Accepted{}, &APIError{StatusCode: resp.StatusCode, Message: er.Error}
	}

	var ar acceptResponse
	if err := json.Unmarshal(data, &ar); err != nil {
		return Accepted{}, fmt.Errorf("client: decode response: %w", err)
	}
	return Accepted(ar), nil
}

// encodePayload turns e.Payload into a payload_json object: nil is omitted, a
// json.RawMessage/[]byte is passed through after a validity check, and anything
// else is JSON-marshaled.
func encodePayload(p any) (json.RawMessage, error) {
	switch v := p.(type) {
	case nil:
		return nil, nil
	case json.RawMessage:
		if !json.Valid(v) {
			return nil, errors.New("client: Payload is not valid JSON")
		}
		return v, nil
	case []byte:
		if !json.Valid(v) {
			return nil, errors.New("client: Payload is not valid JSON")
		}
		return json.RawMessage(v), nil
	default:
		b, err := json.Marshal(p)
		if err != nil {
			return nil, fmt.Errorf("client: marshal payload: %w", err)
		}
		return b, nil
	}
}
