package agent

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPlanesAreSeparated proves the ingest and control planes serve disjoint
// route sets: control routes are unreachable from the ingest mux and vice versa,
// so a loopback ingest client can never rotate or revoke the signing key (§6).
func TestPlanesAreSeparated(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()

	ingest := httptest.NewServer(a.IngestHandler())
	defer ingest.Close()
	control := httptest.NewServer(a.ControlHandler())
	defer control.Close()

	cases := []struct {
		name   string
		base   string
		path   string
		body   string
		status int
	}{
		{"control serves rotate", control.URL, "/v1/rotate-key", `{"reason":"test"}`, http.StatusOK},
		{"control serves revoke", control.URL, "/v1/revoke-key", `{"reason":"test"}`, http.StatusOK},
		{"ingest rejects rotate", ingest.URL, "/v1/rotate-key", `{"reason":"test"}`, http.StatusNotFound},
		{"ingest rejects revoke", ingest.URL, "/v1/revoke-key", `{"reason":"test"}`, http.StatusNotFound},
		{"ingest serves heartbeat", ingest.URL, "/v1/heartbeat", ``, http.StatusOK},
		{"control rejects events", control.URL, "/v1/events", `{"event_type":"system.heartbeat","outcome":""}`, http.StatusNotFound},
		{"control rejects heartbeat", control.URL, "/v1/heartbeat", ``, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tc.base+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

// TestServeRejectsNonLoopback proves Serve refuses a non-loopback ingest bind
// address when unsafeBind is false.
func TestServeRejectsNonLoopback(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := a.Serve(ctx, "0.0.0.0:0", false)
	if err == nil {
		t.Fatal("Serve must reject a non-loopback bind addr when unsafeBind is false")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error should explain the loopback constraint, got: %v", err)
	}
}

// TestServeControlSocket proves Serve binds the control plane on an owner-only
// (0600) unix socket in the key directory and that it answers a rotate request.
func TestServeControlSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx, "127.0.0.1:0", false) }()

	sockPath := a.controlSocketPath()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket was not created within 3 seconds")
		}
		time.Sleep(10 * time.Millisecond)
	}

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("control socket perms = %o, want 0600", perm)
	}

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/rotate-key", strings.NewReader(`{"reason":"socket test"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("control socket rotate request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate over control socket: status = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not shut down within 3 seconds after cancel")
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("control socket should be removed on shutdown, stat err = %v", err)
	}
}
