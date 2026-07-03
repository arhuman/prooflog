package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadConfig covers LoadConfig and the SaltStorePath defaulting logic.
func TestLoadConfig(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadConfig("/no/such/path/config.json"); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "cfg.json")
		if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("validation failure missing source_id", func(t *testing.T) {
		m := map[string]any{
			// source_id intentionally absent
			"org": "acme", "spool_dir": "/tmp/sp",
			"agent_key": "/tmp/ak", "org_recipient": "age1test",
		}
		b, _ := json.Marshal(m)
		path := filepath.Join(t.TempDir(), "cfg.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatal("expected validation error for missing source_id")
		}
	})

	t.Run("defaults applied and salt_store defaulted", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "agent.key")
		m := map[string]any{
			"source_id":     "vps-01/api",
			"org":           "acme",
			"spool_dir":     filepath.Join(dir, "spool"),
			"agent_key":     keyPath,
			"org_recipient": "age1testrecipient",
		}
		b, _ := json.Marshal(m)
		path := filepath.Join(dir, "cfg.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.SourceID != "vps-01/api" {
			t.Fatalf("SourceID = %q, want vps-01/api", cfg.SourceID)
		}
		// SaltStorePath must default to beside the agent key.
		wantSalt := filepath.Join(dir, "salts.json")
		if cfg.SaltStorePath != wantSalt {
			t.Fatalf("SaltStorePath = %q, want %q", cfg.SaltStorePath, wantSalt)
		}
		// Defaults from DefaultConfig should survive.
		if cfg.HeartbeatInterval <= 0 {
			t.Fatal("HeartbeatInterval should have a default")
		}
	})

	t.Run("explicit salt_store_path preserved", func(t *testing.T) {
		dir := t.TempDir()
		saltPath := filepath.Join(dir, "custom-salts.json")
		m := map[string]any{
			"source_id":     "vps-01/api",
			"org":           "acme",
			"spool_dir":     filepath.Join(dir, "spool"),
			"agent_key":     filepath.Join(dir, "agent.key"),
			"org_recipient": "age1testrecipient",
			"salt_store":    saltPath,
		}
		b, _ := json.Marshal(m)
		path := filepath.Join(dir, "cfg.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.SaltStorePath != saltPath {
			t.Fatalf("SaltStorePath = %q, want %q", cfg.SaltStorePath, saltPath)
		}
	})
}

// TestConfigValidate covers each required-field check in Config.validate.
func TestConfigValidate(t *testing.T) {
	full := Config{
		SourceID:     "vps-01/api",
		Org:          "acme",
		SpoolDir:     "/tmp/spool",
		AgentKeyPath: "/tmp/agent.key",
		OrgRecipient: "age1testrecipient",
	}
	if err := full.validate(); err != nil {
		t.Fatalf("fully-populated config: unexpected error: %v", err)
	}

	cases := []struct {
		name string
		mod  func(Config) Config
	}{
		{"missing source_id", func(c Config) Config { c.SourceID = ""; return c }},
		{"missing org", func(c Config) Config { c.Org = ""; return c }},
		{"missing spool_dir", func(c Config) Config { c.SpoolDir = ""; return c }},
		{"missing agent_key", func(c Config) Config { c.AgentKeyPath = ""; return c }},
		{"missing org_recipient", func(c Config) Config { c.OrgRecipient = ""; return c }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.mod(full).validate(); err == nil {
				t.Fatalf("validate: want error for %s, got nil", tc.name)
			}
		})
	}
}

// TestSpoolPolicyDropOldest covers the "drop-oldest" branch in Config.spoolPolicy.
func TestSpoolPolicyDropOldest(_ *testing.T) {
	c := DefaultConfig()
	c.SpoolPolicy = "drop-oldest"
	_ = c.spoolPolicy() // just ensure the branch is taken without panic
}

// TestDurationUnmarshalErrors covers the two error branches in Duration.UnmarshalJSON.
func TestDurationUnmarshalErrors(t *testing.T) {
	var d Duration

	// Non-string JSON value → json.Unmarshal error.
	if err := json.Unmarshal([]byte(`123`), &d); err == nil {
		t.Fatal("expected error for non-string duration JSON")
	}

	// String value that is not a valid duration → time.ParseDuration error.
	if err := json.Unmarshal([]byte(`"not-a-valid-duration"`), &d); err == nil {
		t.Fatal("expected error for invalid duration string")
	}
}

// TestHTTPHeartbeat covers handleHeartbeat (currently 0%).
func TestHTTPHeartbeat(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()
	srv := httptest.NewServer(a.IngestHandler())
	defer srv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/heartbeat", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("handleHeartbeat: status = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Seq       uint64 `json:"seq"`
		EventType string `json:"event_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode heartbeat response: %v", err)
	}
	if out.EventType != "system.heartbeat" {
		t.Fatalf("event_type = %q, want system.heartbeat", out.EventType)
	}
}

// TestHTTPEventBadEventTime covers the RFC3339 parse error branch in handleEvent.
func TestHTTPEventBadEventTime(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()
	srv := httptest.NewServer(a.IngestHandler())
	defer srv.Close()

	body := `{"event_type":"system.heartbeat","event_time":"not-rfc3339"}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/events", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad event_time: status = %d, want 400", resp.StatusCode)
	}
}

// TestHTTPEventInvalidOutcome covers the outcome validation branch in handleEvent.
func TestHTTPEventInvalidOutcome(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()
	srv := httptest.NewServer(a.IngestHandler())
	defer srv.Close()

	body := `{"event_type":"access.revoked","outcome":"definitely-not-a-valid-outcome"}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/events", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid outcome: status = %d, want 400", resp.StatusCode)
	}
}

// TestHTTPEventInvalidJSONBody covers the json.Decode error branch in handleEvent.
func TestHTTPEventInvalidJSONBody(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()
	srv := httptest.NewServer(a.IngestHandler())
	defer srv.Close()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/events", strings.NewReader("not-json-at-all"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid JSON body: status = %d, want 400", resp.StatusCode)
	}
}

// TestAcceptEventRejectsInvalidOutcome covers the allowedOutcomes() code path
// inside AcceptEvent (currently 0%).
func TestAcceptEventRejectsInvalidOutcome(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()
	if _, err := a.AcceptEvent(EventInput{
		EventType: "access.revoked",
		Outcome:   "definitely-not-valid",
	}); err == nil {
		t.Fatal("AcceptEvent should reject an outcome not in the allowed set")
	}
}

// TestServe covers the Serve function: it starts listening, handles a context
// cancellation, and shuts down gracefully.
func TestServe(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- a.Serve(ctx, "127.0.0.1:0", false)
	}()

	// Allow the server time to bind and start serving before cancelling.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not shut down within 3 seconds after context cancel")
	}
}
