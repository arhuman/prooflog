package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// decodeReq reads the outgoing eventRequest and its raw payload_json.
func decodeReq(t *testing.T, r *http.Request) (eventRequest, map[string]any) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var req eventRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	var payload map[string]any
	if len(req.Payload) > 0 {
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			t.Fatalf("unmarshal payload_json: %v", err)
		}
	}
	return req, payload
}

func TestSend_RequestShapeAndAccepted(t *testing.T) {
	var got eventRequest
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/events" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		got, payload = decodeReq(t, r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(acceptResponse{Seq: 42, RecordHash: "abc123", EventType: got.EventType})
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"))
	type deploy struct {
		Service string `json:"service"`
		Version string `json:"version"`
	}
	acc, err := c.Send(context.Background(), Event{
		Type:    EventDeployCompleted,
		Actor:   "ci@acme",
		Outcome: OutcomeSuccess,
		Labels:  map[string]string{"env": "prod"},
		Payload: deploy{Service: "api", Version: "1.2.3"},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got.EventType != "deploy.completed" {
		t.Errorf("event_type = %q", got.EventType)
	}
	if got.Actor != "ci@acme" {
		t.Errorf("actor = %q", got.Actor)
	}
	if got.Outcome != "success" {
		t.Errorf("outcome = %q", got.Outcome)
	}
	if got.Labels["env"] != "prod" {
		t.Errorf("labels = %v", got.Labels)
	}
	if payload["service"] != "api" || payload["version"] != "1.2.3" {
		t.Errorf("payload_json = %v", payload)
	}
	if acc.Seq != 42 || acc.RecordHash != "abc123" || acc.EventType != "deploy.completed" {
		t.Errorf("accepted = %+v", acc)
	}
}

func TestSend_TimeOmittedWhenZero(t *testing.T) {
	var got eventRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = decodeReq(t, r)
		_ = json.NewEncoder(w).Encode(acceptResponse{Seq: 1})
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"))
	if _, err := c.Send(context.Background(), Event{Type: EventBackupCompleted}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got.EventTime != "" {
		t.Errorf("event_time should be omitted, got %q", got.EventTime)
	}

	when := time.Date(2026, 7, 4, 10, 30, 0, 0, time.UTC)
	if _, err := c.Send(context.Background(), Event{Type: EventBackupCompleted, Time: when}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got.EventTime == "" {
		t.Errorf("event_time should be set")
	}
}

func TestSend_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: "event_type is required"})
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"))
	_, err := c.Send(context.Background(), Event{Type: EventDataExported})
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", apiErr.StatusCode)
	}
	if apiErr.Message != "event_type is required" {
		t.Errorf("message = %q", apiErr.Message)
	}
}

func TestSend_InvalidOutcomeRejectedBeforeHTTP(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"))
	_, err := c.Send(context.Background(), Event{Type: EventAccessGranted, Outcome: "bogus"})
	if err == nil {
		t.Fatal("expected error")
	}
	if called {
		t.Error("HTTP call should not happen for invalid outcome")
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		t.Error("invalid outcome must be a local error, not *APIError")
	}
}

func TestSend_SystemTypeRejected(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"))
	_, err := c.Send(context.Background(), Event{Type: "system.heartbeat"})
	if err == nil {
		t.Fatal("expected error")
	}
	if called {
		t.Error("HTTP call should not happen for system.* type")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error should mention reserved: %v", err)
	}
}

func TestSend_EmptyTypeRejected(t *testing.T) {
	c := New("")
	if _, err := c.Send(context.Background(), Event{}); err == nil {
		t.Fatal("expected error for empty Type")
	}
}

func TestSend_OversizedResponseBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		blob := strings.Repeat("a", (maxRespBytes + 10))
		_, _ = io.WriteString(w, `{"junk":"`+blob+`"}`)
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"))
	_, err := c.Send(context.Background(), Event{Type: EventIncidentDetected})
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("want size error, got %v", err)
	}
}

func TestSend_RawMessagePayloadPassthrough(t *testing.T) {
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, payload = decodeReq(t, r)
		_ = json.NewEncoder(w).Encode(acceptResponse{Seq: 1})
	}))
	defer srv.Close()

	c := New(strings.TrimPrefix(srv.URL, "http://"))
	if _, err := c.Send(context.Background(), Event{
		Type:    EventSecretRotated,
		Payload: json.RawMessage(`{"kid":"k1"}`),
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if payload["kid"] != "k1" {
		t.Errorf("payload = %v", payload)
	}
}

func TestSend_InvalidRawPayloadRejected(t *testing.T) {
	c := New("")
	_, err := c.Send(context.Background(), Event{
		Type:    EventSecretRotated,
		Payload: json.RawMessage(`{not json`),
	})
	if err == nil {
		t.Fatal("expected error for invalid raw payload")
	}
}

func TestNew_DefaultsAndOptions(t *testing.T) {
	c := New("")
	if c.baseURL != "http://127.0.0.1:9600" {
		t.Errorf("default baseURL = %q", c.baseURL)
	}
	custom := &http.Client{Timeout: time.Second}
	c2 := New("10.0.0.1:1234", WithHTTPClient(custom), WithTimeout(2*time.Second))
	if c2.baseURL != "http://10.0.0.1:1234" {
		t.Errorf("baseURL = %q", c2.baseURL)
	}
	if c2.http != custom {
		t.Error("WithHTTPClient should be used as-is")
	}
	c3 := New("host:1", WithTimeout(3*time.Second))
	if c3.http.Timeout != 3*time.Second {
		t.Errorf("timeout = %v", c3.http.Timeout)
	}
}
