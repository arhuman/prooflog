package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/arhuman/prooflog/internal/envelope"
)

const maxBodyBytes = 4 << 20

// eventRequest is the JSON body of POST /v1/events. The external API is
// unchanged: callers still send a plaintext actor and free-text labels. The
// agent transforms them before anything is hashed — actor becomes an erasable
// HMAC pseudonym and labels are folded into the encrypted payload (WS4), so
// neither the plaintext actor nor the label text ever enters the record bytes.
type eventRequest struct {
	EventType string            `json:"event_type"`
	EventTime string            `json:"event_time,omitempty"`
	Actor     string            `json:"actor,omitempty"`
	Outcome   string            `json:"outcome,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Payload   json.RawMessage   `json:"payload_json,omitempty"`
}

// acceptResponse is returned once a record is durably accepted.
type acceptResponse struct {
	Seq        uint64 `json:"seq"`
	RecordHash string `json:"record_hash"`
	EventType  string `json:"event_type"`
}

// IngestHandler returns the agent's local data-plane HTTP handler (REQ-E-04). It
// exposes only the unprivileged ingest routes POST /v1/events and
// POST /v1/heartbeat. The privileged key-lifecycle routes live on a separate
// control plane (see ControlHandler) so a loopback ingest client can never reach
// them (§6).
func (a *Agent) IngestHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/events", a.handleEvent)
	mux.HandleFunc("POST /v1/heartbeat", a.handleHeartbeat)
	return mux
}

// ControlHandler returns the agent's privileged control-plane HTTP handler. It
// exposes POST /v1/rotate-key and POST /v1/revoke-key, which can DoS or forge the
// agent's Ed25519 signing key. It is served only over the owner-only unix socket
// bound by Serve, so access is gated by OS filesystem permissions (§6).
func (a *Agent) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/rotate-key", a.handleRotateKey)
	mux.HandleFunc("POST /v1/revoke-key", a.handleRevokeKey)
	return mux
}

// rotateRequest is the JSON body of POST /v1/rotate-key.
type rotateRequest struct {
	Reason string `json:"reason,omitempty"`
}

// revokeRequest is the JSON body of POST /v1/revoke-key.
type revokeRequest struct {
	Reason         string `json:"reason,omitempty"`
	SuspectedSince string `json:"suspected_since,omitempty"`
}

func (a *Agent) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	defer drain(r.Body)
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req rotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	res, err := a.RotateKey(req.Reason)
	if err != nil {
		a.log.Error("rotate key", "err", err)
		writeErr(w, http.StatusInternalServerError, "could not rotate key")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *Agent) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	defer drain(r.Body)
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	rec, err := a.RevokeKey(req.Reason, req.SuspectedSince)
	if err != nil {
		a.log.Error("revoke key", "err", err)
		writeErr(w, http.StatusInternalServerError, "could not revoke key")
		return
	}
	writeAccepted(w, rec)
}

func (a *Agent) handleEvent(w http.ResponseWriter, r *http.Request) {
	defer drain(r.Body)
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req eventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.EventType == "" {
		writeErr(w, http.StatusBadRequest, "event_type is required")
		return
	}
	if !envelope.ValidOutcomes[req.Outcome] {
		writeErr(w, http.StatusBadRequest, "outcome must be one of: "+allowedOutcomes())
		return
	}
	in := EventInput{
		EventType: req.EventType,
		Actor:     req.Actor,
		Outcome:   req.Outcome,
		Labels:    req.Labels,
		Payload:   req.Payload,
	}
	if req.EventTime != "" {
		t, err := time.Parse(time.RFC3339Nano, req.EventTime)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "event_time must be RFC3339")
			return
		}
		in.EventTime = t
	}
	rec, err := a.AcceptEvent(in)
	if err != nil {
		a.log.Error("accept event", "err", err)
		writeErr(w, http.StatusInternalServerError, "could not accept event")
		return
	}
	writeAccepted(w, rec)
}

func (a *Agent) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	defer drain(r.Body)
	rec, err := a.Heartbeat()
	if err != nil {
		a.log.Error("forced heartbeat", "err", err)
		writeErr(w, http.StatusInternalServerError, "could not emit heartbeat")
		return
	}
	writeAccepted(w, rec)
}

func writeAccepted(w http.ResponseWriter, rec envelope.Record) {
	writeJSON(w, http.StatusOK, acceptResponse{
		Seq:        rec.Seq,
		RecordHash: rec.HashHex(),
		EventType:  rec.EventType,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func drain(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxBodyBytes))
	_ = body.Close()
}

// Serve runs the agent's two local listeners until ctx is cancelled: a loopback
// TCP ingest plane on addr (POST /v1/events, /v1/heartbeat) and a privileged
// control plane (POST /v1/rotate-key, /v1/revoke-key) on a unix domain socket in
// the agent's 0700 key directory. The control plane is authenticated by OS
// filesystem permissions — the same trust model that guards the signing key —
// rather than a bearer token (§6). Ingest is local-only by design: a non-loopback
// bind addr is rejected unless unsafeBind is set (the --insecure-style opt-out).
func (a *Agent) Serve(ctx context.Context, addr string, unsafeBind bool) error {
	if err := ensureLoopback(ctx, addr, unsafeBind); err != nil {
		return err
	}

	ingest := &http.Server{
		Addr:              addr,
		Handler:           a.IngestHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	ingestLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}

	sockPath := a.controlSocketPath()
	control := &http.Server{
		Handler:           a.ControlHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	controlLn, err := listenControlSocket(ctx, sockPath)
	if err != nil {
		_ = ingestLn.Close()
		return err
	}

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ingest.Shutdown(sctx)  //nolint:contextcheck // detached shutdown context outlives the cancelled server ctx
		_ = control.Shutdown(sctx) //nolint:contextcheck // detached shutdown context outlives the cancelled server ctx
		_ = os.Remove(sockPath)
	}()

	a.log.Info("agent HTTP listeners started", "ingest", addr, "control", sockPath)

	errCh := make(chan error, 2)
	go func() { errCh <- serveListener(ingest, ingestLn) }()
	go func() { errCh <- serveListener(control, controlLn) }()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// serveListener runs srv on ln, treating a graceful shutdown as success.
func serveListener(srv *http.Server, ln net.Listener) error {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ControlSocketPath is the unix domain socket for the privileged control plane.
// It lives in the agent's 0700 key directory so filesystem permissions gate who
// may rotate or revoke the signing key (§6). It is the single source of truth for
// the socket location, shared by the daemon and the `prooflog key` CLI client.
func ControlSocketPath(cfg Config) string {
	return filepath.Join(filepath.Dir(cfg.AgentKeyPath), "control.sock")
}

func (a *Agent) controlSocketPath() string {
	return ControlSocketPath(a.cfg)
}

// listenControlSocket binds the control-plane unix socket, removing any stale
// socket file first and tightening the socket to owner-only (0600).
func listenControlSocket(ctx context.Context, path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("agent: remove stale control socket: %w", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("agent: listen control socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("agent: chmod control socket: %w", err)
	}
	return ln, nil
}

// ensureLoopback rejects a non-loopback ingest bind address unless unsafeBind is
// set. Ingest is local-only by design (§6); loopback is decided by resolving the
// host and checking net.IP.IsLoopback.
func ensureLoopback(ctx context.Context, addr string, unsafeBind bool) error {
	if unsafeBind {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("agent: invalid ingest addr %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("agent: ingest addr %q binds all interfaces; ingest is local-only (§6). Set unsafeBind (--unsafe-bind) to override", addr)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("agent: resolve ingest host %q: %w", host, err)
	}
	for _, ip := range ips {
		if !ip.IP.IsLoopback() {
			return fmt.Errorf("agent: ingest addr %q resolves to non-loopback %s; ingest is local-only (§6). Set unsafeBind (--unsafe-bind) to override", addr, ip.IP)
		}
	}
	return nil
}
