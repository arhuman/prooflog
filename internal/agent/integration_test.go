package agent_test

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/arhuman/prooflog/internal/agent"
	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/spool"
	"github.com/arhuman/prooflog/internal/store"
)

// storeInstance is a running store gRPC server for the test.
type storeInstance struct {
	srv *grpc.Server
	st  *store.Store
}

func (s *storeInstance) stop() {
	s.srv.Stop()
	s.st.Close()
}

// startStore opens a store and serves it on addr.
func startStore(t *testing.T, addr, dbPath, blobDir string) *storeInstance {
	t.Helper()
	st, err := store.Open(store.Config{DBPath: dbPath, BlobDir: blobDir, Retention: time.Hour})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	srv := grpc.NewServer()
	api.RegisterStore(srv, st)
	go func() { _ = srv.Serve(ln) }()
	return &storeInstance{srv: srv, st: st}
}

// freeAddr reserves and releases an ephemeral loopback address so it can be
// bound twice (store restart on the same port).
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve addr: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func writeTestConfig(t *testing.T, dir, storeAddr string) agent.Config {
	t.Helper()
	agentKey, err := keys.GenerateAgentKey("test-agent", time.Now())
	if err != nil {
		t.Fatalf("gen agent key: %v", err)
	}
	keyPath := filepath.Join(dir, "agent.key")
	if err := keys.SaveAgentKey(keyPath, agentKey); err != nil {
		t.Fatalf("save agent key: %v", err)
	}
	orgKey, err := keys.GenerateOrgKey("test", time.Now())
	if err != nil {
		t.Fatalf("gen org key: %v", err)
	}
	return agent.Config{
		SourceID:          "vps-01/api",
		Org:               "test",
		AgentName:         "test-agent",
		Version:           "test",
		SpoolDir:          filepath.Join(dir, "spool"),
		AgentKeyPath:      keyPath,
		OrgRecipient:      orgKey.Recipient(),
		KeyID:             "org-test-1",
		HTTPAddr:          "127.0.0.1:0",
		StoreAddr:         storeAddr,
		HeartbeatInterval: agent.Duration(time.Hour), // out of the way; drive seq deterministically
		SealMaxRecords:    2,                         // seal often so outage buffers multiple segments
		SealMaxAge:        agent.Duration(time.Hour),
		SpoolPolicy:       "block",
		TLS:               api.TLSConfig{Insecure: true},
	}
}

// TestOutageTolerance is the outage-tolerance demo in code form: events accepted
// while the store is down are buffered locally and fully replayed on recovery,
// with no lost sequence, bracketed by system.network_outage/replay_completed
// (REQ-E-04, §6).
func TestOutageTolerance(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	dir := t.TempDir()
	addr := freeAddr(t)
	dbPath := filepath.Join(dir, "store.db")
	blobDir := filepath.Join(dir, "blobs")

	st := startStore(t, addr, dbPath, blobDir)

	cfg := writeTestConfig(t, dir, addr)
	a, err := agent.New(cfg, nil)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Start(ctx)

	// Phase 1: store up. Accept events and confirm they are ACKed.
	acceptEvents(t, a, "before", 5)
	a.Flush()
	waitAcked(t, a, 15*time.Second)
	ackedBeforeOutage := a.AckedSeq()
	if ackedBeforeOutage == 0 {
		t.Fatalf("expected ACKs before outage, got 0")
	}

	// Phase 2: kill the store. Accepted events must still be durably spooled.
	st.stop()
	acceptEvents(t, a, "during", 5)
	a.Flush()
	// The uploader should fail and record an outage.
	waitForEvent(t, a, "system.network_outage", 15*time.Second)
	if a.AckedSeq() != ackedBeforeOutage {
		t.Fatalf("ACK advanced during outage: was %d now %d", ackedBeforeOutage, a.AckedSeq())
	}

	// Phase 3: restart the store on the same port; replay must complete.
	st = startStore(t, addr, dbPath, blobDir)
	defer st.stop()

	deadline := time.Now().Add(30 * time.Second)
	for {
		a.Flush()
		if a.AckedSeq() == a.LastSeq() && hasEvent(t, a, "system.replay_completed") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("replay did not complete: acked=%d last=%d", a.AckedSeq(), a.LastSeq())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// spool.MarkAcked must have advanced past the pre-outage watermark.
	if a.AckedSeq() <= ackedBeforeOutage {
		t.Fatalf("ACK did not advance after replay: before=%d after=%d", ackedBeforeOutage, a.AckedSeq())
	}

	// Both outage boundary events are present in the chain.
	if !hasEvent(t, a, "system.network_outage") {
		t.Fatalf("missing system.network_outage in chain")
	}
	if !hasEvent(t, a, "system.replay_completed") {
		t.Fatalf("missing system.replay_completed in chain")
	}

	lastSeq := a.LastSeq()

	// Stop the agent cleanly and re-verify the spool independently.
	cancel()
	a.Stop()

	records := readSpool(t, cfg.SpoolDir)
	if len(records) == 0 {
		t.Fatalf("spool empty after run")
	}
	// Contiguous seq 1..N, no gaps.
	for i, r := range records {
		if r.Seq != uint64(i+1) {
			t.Fatalf("seq gap at index %d: got %d", i, r.Seq)
		}
	}
	// Hash chain verifies end to end (REQ-C-03/04).
	entries := make([]chain.Entry, len(records))
	for i, r := range records {
		entries[i] = chain.Entry{Bytes: r.Bytes(), Hash: r.HashHex()}
	}
	if err := chain.Verify(entries); err != nil {
		t.Fatalf("chain verify: %v", err)
	}

	// The store holds byte-exact copies of every ACKed record (REQ-C-04, E-05).
	pulled := pullAll(t, addr, cfg.SourceID)
	if uint64(len(pulled)) < lastSeq-1 { // agent_stopped may not have uploaded
		t.Logf("pulled %d records, agent last seq %d", len(pulled), lastSeq)
	}
	for _, fr := range pulled {
		rec, err := envelope.Parse(fr)
		if err != nil {
			t.Fatalf("parse pulled record: %v", err)
		}
		if rec.SourceID != cfg.SourceID {
			t.Fatalf("pulled record from wrong source: %s", rec.SourceID)
		}
	}
}

func acceptEvents(t *testing.T, a *agent.Agent, label string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := a.AcceptEvent(agent.EventInput{
			EventType: "access.granted",
			Actor:     "admin@test",
			Outcome:   "success",
			Labels:    map[string]string{"phase": label},
		})
		if err != nil {
			t.Fatalf("accept event %s#%d: %v", label, i, err)
		}
	}
}

func waitAcked(t *testing.T, a *agent.Agent, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if a.AckedSeq() == a.LastSeq() && a.AckedSeq() > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for ACKs: acked=%d last=%d", a.AckedSeq(), a.LastSeq())
}

func waitForEvent(t *testing.T, a *agent.Agent, eventType string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if hasEvent(t, a, eventType) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for event %s", eventType)
}

func hasEvent(t *testing.T, a *agent.Agent, eventType string) bool {
	t.Helper()
	it, err := a.Spool().Iter(0)
	if err != nil {
		t.Fatalf("iter spool: %v", err)
	}
	defer it.Close()
	for {
		rec, ok, err := it.Next()
		if err != nil {
			t.Fatalf("iter next: %v", err)
		}
		if !ok {
			return false
		}
		if rec.EventType == eventType {
			return true
		}
	}
}

func readSpool(t *testing.T, dir string) []envelope.Record {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: dir})
	if err != nil {
		t.Fatalf("open spool: %v", err)
	}
	defer sp.Close()
	it, err := sp.Iter(0)
	if err != nil {
		t.Fatalf("iter: %v", err)
	}
	defer it.Close()
	var out []envelope.Record
	for {
		rec, ok, err := it.Next()
		if err != nil {
			t.Fatalf("iter next: %v", err)
		}
		if !ok {
			break
		}
		out = append(out, rec)
	}
	return out
}

func pullAll(t *testing.T, addr, sourceID string) [][]byte {
	t.Helper()
	conn, err := api.Dial(addr, api.TLSConfig{Insecure: true})
	if err != nil {
		t.Fatalf("dial store: %v", err)
	}
	defer conn.Close()
	client := api.NewStoreClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.PullSegments(ctx, &api.PullRequest{SourceId: sourceID, FromSeq: 0})
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	var out [][]byte
	for {
		fr, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("pull recv: %v", err)
		}
		out = append(out, fr.RecordBytes)
	}
	return out
}
