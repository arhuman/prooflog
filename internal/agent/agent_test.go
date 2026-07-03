package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/seal"
	"github.com/arhuman/prooflog/internal/store"
)

// testAgent builds an agent with fresh keys and a temp spool, dialing storeAddr
// (which may be a dead address for local-only tests).
func testAgent(t *testing.T, storeAddr string, maxRecords int) *Agent {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "agent.key")
	ak, err := keys.GenerateAgentKey("vps-01-api", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveAgentKey(keyPath, ak); err != nil {
		t.Fatal(err)
	}
	org, err := keys.GenerateOrgKey("org-acme-2026-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.SourceID = "vps-01/api"
	cfg.Org = "acme"
	cfg.AgentName = "vps-01-api"
	cfg.SpoolDir = filepath.Join(dir, "spool")
	cfg.AgentKeyPath = keyPath
	cfg.OrgRecipient = org.Recipient()
	cfg.KeyID = "org-acme-2026-1"
	cfg.StoreAddr = storeAddr
	cfg.SealMaxRecords = maxRecords
	cfg.TLS = api.TLSConfig{Insecure: true}

	a, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAgentIngestAssignsSeqAndChains(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()

	r1, err := a.AcceptEvent(EventInput{EventType: "system.heartbeat"})
	if err != nil {
		t.Fatal(err)
	}
	if r1.Seq != 1 || r1.PrevHash != chain.Genesis {
		t.Fatalf("first record: seq=%d prev=%s", r1.Seq, r1.PrevHash)
	}
	r2, err := a.AcceptEvent(EventInput{EventType: "system.agent_started"})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Seq != 2 || r2.PrevHash != r1.HashHex() {
		t.Fatalf("second record not chained: seq=%d prev=%s", r2.Seq, r2.PrevHash)
	}
	if a.LastSeq() != 2 {
		t.Fatalf("LastSeq = %d, want 2", a.LastSeq())
	}
}

func TestAgentEncryptsBusinessPayload(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()

	rec, err := a.AcceptEvent(EventInput{
		EventType: "access.revoked",
		Actor:     "admin@acme",
		Outcome:   "success",
		Payload:   json.RawMessage(`{"user":"bob"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.PayloadCT == "" || rec.PayloadHash == "" || rec.KeyID != "org-acme-2026-1" {
		t.Fatalf("business payload not sealed: %+v", rec)
	}
	if len(rec.PayloadClear) != 0 {
		t.Fatal("business event must not carry payload_clear")
	}
	if strings.Contains(rec.PayloadCT, "bob") {
		t.Fatal("plaintext leaked into ciphertext field")
	}
}

func TestAgentPseudonymizesActorAndWrapsLabels(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "agent.key")
	ak, err := keys.GenerateAgentKey("vps-01-api", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveAgentKey(keyPath, ak); err != nil {
		t.Fatal(err)
	}
	org, err := keys.GenerateOrgKey("org-acme-2026-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.SourceID = "vps-01/api"
	cfg.Org = "acme"
	cfg.AgentName = "vps-01-api"
	cfg.SpoolDir = filepath.Join(dir, "spool")
	cfg.AgentKeyPath = keyPath
	cfg.OrgRecipient = org.Recipient()
	cfg.KeyID = "org-acme-2026-1"
	cfg.StoreAddr = "127.0.0.1:0"
	cfg.SealMaxRecords = 1000
	cfg.TLS = api.TLSConfig{Insecure: true}

	a, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()

	rec, err := a.AcceptEvent(EventInput{
		EventType: "access.revoked",
		Actor:     "alice@acme",
		Outcome:   "success",
		Labels:    map[string]string{"team": "x"},
		Payload:   json.RawMessage(`{"user":"bob"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The raw personal strings must never appear in the hashed bytes.
	raw := string(rec.Bytes())
	for _, forbidden := range []string{"alice@acme", "team"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("personal data leaked into record bytes: %q\n%s", forbidden, raw)
		}
	}
	// Actor is a 64-hex pseudonym.
	if len(rec.Actor) != 64 {
		t.Fatalf("actor is not a 64-hex pseudonym: %q", rec.Actor)
	}
	if _, err := hex.DecodeString(rec.Actor); err != nil {
		t.Fatalf("actor is not hex: %v", err)
	}

	// Decrypt the payload with the org identity: labels round-trip in the wrapper.
	ct, err := seal.DecodeBase64(rec.PayloadCT)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := seal.AgeSealer{}.Open(ct, org.Identity)
	if err != nil {
		t.Fatal(err)
	}
	var wrapped struct {
		Labels map[string]string `json:"labels"`
		Data   json.RawMessage   `json:"data"`
	}
	if err := json.Unmarshal(plain, &wrapped); err != nil {
		t.Fatalf("unmarshal wrapped payload: %v", err)
	}
	if wrapped.Labels["team"] != "x" {
		t.Fatalf("labels did not round-trip: %+v", wrapped.Labels)
	}
	if string(wrapped.Data) != `{"user":"bob"}` {
		t.Fatalf("payload data did not round-trip: %s", wrapped.Data)
	}
}

func TestAgentSystemEventCarriesClearPayload(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()
	rec, err := a.AcceptEvent(EventInput{EventType: "system.network_outage", Payload: json.RawMessage(`{"last_ack_seq":5}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.PayloadClear) == 0 || rec.PayloadCT != "" {
		t.Fatalf("system event should carry clear payload: %+v", rec)
	}
}

func TestAgentSpooledChainVerifies(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	for i := 0; i < 5; i++ {
		if _, err := a.AcceptEvent(EventInput{EventType: "system.heartbeat"}); err != nil {
			t.Fatal(err)
		}
	}
	entries := spooledEntries(t, a)
	a.Stop()
	if err := chain.Verify(entries); err != nil {
		t.Fatalf("spooled chain invalid: %v", err)
	}
}

func TestAgentHeartbeat(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()
	rec, err := a.Heartbeat()
	if err != nil {
		t.Fatal(err)
	}
	if rec.EventType != "system.heartbeat" || len(rec.PayloadClear) == 0 {
		t.Fatalf("bad heartbeat: %+v", rec)
	}
}

func TestAgentRecoversAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "agent.key")
	ak, _ := keys.GenerateAgentKey("vps-01-api", time.Now())
	if err := keys.SaveAgentKey(keyPath, ak); err != nil {
		t.Fatal(err)
	}
	org, _ := keys.GenerateOrgKey("org", time.Now())

	cfg := DefaultConfig()
	cfg.SourceID = "vps-01/api"
	cfg.Org = "acme"
	cfg.SpoolDir = filepath.Join(dir, "spool")
	cfg.AgentKeyPath = keyPath
	cfg.OrgRecipient = org.Recipient()
	cfg.KeyID = "k"
	cfg.StoreAddr = "127.0.0.1:0"
	cfg.SealMaxRecords = 1000
	cfg.TLS = api.TLSConfig{Insecure: true}

	a1, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := a1.AcceptEvent(EventInput{EventType: "system.heartbeat"}); err != nil {
			t.Fatal(err)
		}
	}
	seqBefore := a1.LastSeq()
	a1.Stop() // records system.agent_stopped, then closes spool

	a2, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Stop()
	if a2.LastSeq() < seqBefore {
		t.Fatalf("recovered LastSeq %d < %d", a2.LastSeq(), seqBefore)
	}
	next, err := a2.AcceptEvent(EventInput{EventType: "system.heartbeat"})
	if err != nil {
		t.Fatal(err)
	}
	if next.Seq != a2.LastSeq() || next.Seq <= seqBefore {
		t.Fatalf("post-recovery seq not continued: %d", next.Seq)
	}
	// The full chain across the restart must still verify.
	if err := chain.Verify(spooledEntries(t, a2)); err != nil {
		t.Fatalf("chain across restart invalid: %v", err)
	}
}

func TestAgentHTTPIngest(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()
	srv := httptest.NewServer(a.IngestHandler())
	defer srv.Close()

	body := `{"event_type":"system.heartbeat","payload_json":{"k":1}}`
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out struct {
		Seq        uint64 `json:"seq"`
		RecordHash string `json:"record_hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Seq != 1 || out.RecordHash == "" {
		t.Fatalf("bad accept response: %+v", out)
	}
}

func TestAgentHTTPRejectsMissingEventType(t *testing.T) {
	a := testAgent(t, "127.0.0.1:0", 1000)
	defer a.Stop()
	srv := httptest.NewServer(a.IngestHandler())
	defer srv.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/events", strings.NewReader(`{}`))
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
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAgentUploadEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	addr, _ := startLoopbackStore(t)
	a := testAgent(t, addr, 1) // seal every record so each uploads immediately
	ctx, cancel := context.WithCancel(context.Background())
	a.Start(ctx)

	for i := 0; i < 4; i++ {
		if _, err := a.AcceptEvent(EventInput{EventType: "system.heartbeat"}); err != nil {
			t.Fatal(err)
		}
	}
	target := a.LastSeq()
	waitFor(t, 3*time.Second, func() bool { return a.AckedSeq() >= target })

	// Pull the exact stored bytes back and verify the chain end-to-end.
	entries := pullEntries(t, addr, "vps-01/api")
	cancel()
	a.Stop()
	if len(entries) < int(target) {
		t.Fatalf("store has %d frames, want >= %d", len(entries), target)
	}
	if err := chain.Verify(entries[:target]); err != nil {
		t.Fatalf("end-to-end chain invalid: %v", err)
	}
}

// --- helpers ---

func spooledEntries(t *testing.T, a *Agent) []chain.Entry {
	t.Helper()
	it, err := a.Spool().Iter(0)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	var entries []chain.Entry
	for {
		rec, ok, err := it.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		entries = append(entries, chain.Entry{Bytes: rec.Bytes(), Hash: rec.HashHex()})
	}
	return entries
}

func startLoopbackStore(t *testing.T) (string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(store.Config{DBPath: filepath.Join(dir, "i.db"), BlobDir: filepath.Join(dir, "b")})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	api.RegisterStore(srv, s)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); _ = s.Close() })
	return ln.Addr().String(), s
}

func pullEntries(t *testing.T, addr, sourceID string) []chain.Entry {
	t.Helper()
	cc, err := api.Dial(addr, api.TLSConfig{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	stream, err := api.NewStoreClient(cc).PullSegments(context.Background(), &api.PullRequest{SourceId: sourceID, FromSeq: 1})
	if err != nil {
		t.Fatal(err)
	}
	var entries []chain.Entry
	for {
		fr, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, chain.Entry{Bytes: fr.RecordBytes, Hash: hashHexOf(fr.RecordBytes)})
	}
	return entries
}

func hashHexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
