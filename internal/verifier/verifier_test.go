package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/evidence"
	"github.com/arhuman/prooflog/internal/pseudonym"
	"github.com/arhuman/prooflog/internal/segment"
)

const (
	keyName = "vps-01-api"
	origin  = "prooflog/acme/vps-01/api"
	srcID   = "vps-01/api"
)

// builder assembles a properly chained record stream and matching signed
// checkpoints for one source.
type builder struct {
	t        *testing.T
	prev     string
	seq      uint64
	now      time.Time
	actor    string
	batcher  *segment.Batcher
	entries  []chain.Entry
	checkpts []string
}

func newBuilder(t *testing.T, priv ed25519.PrivateKey) *builder {
	return &builder{
		t:       t,
		prev:    envelope.ZeroHash,
		now:     time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC),
		batcher: segment.New(origin, keyName, priv),
	}
}

func (b *builder) add(eventType string, clearPayload any) {
	b.t.Helper()
	b.seq++
	ts := envelope.FormatTime(b.now)
	rec := envelope.Record{
		Version:    envelope.Version,
		SourceID:   srcID,
		Seq:        b.seq,
		EventType:  eventType,
		EventTime:  ts,
		IngestTime: ts,
		Actor:      b.actor,
		PrevHash:   b.prev,
	}
	if clearPayload != nil {
		raw, err := json.Marshal(clearPayload)
		if err != nil {
			b.t.Fatal(err)
		}
		rec.PayloadClear = raw
	} else {
		rec.PayloadClear = []byte(`{}`)
	}
	if err := rec.Serialize(); err != nil {
		b.t.Fatal(err)
	}
	b.entries = append(b.entries, chain.Entry{Bytes: rec.Bytes(), Hash: rec.HashHex()})
	if err := b.batcher.Add(rec.Bytes(), rec.Seq, b.now); err != nil {
		b.t.Fatal(err)
	}
	b.prev = rec.HashHex()
}

func (b *builder) heartbeat(driftMS int64) {
	b.add(evHeartbeat, map[string]any{"health": map[string]any{"clock_drift_ms": driftMS}})
}

func (b *builder) tick(d time.Duration) { b.now = b.now.Add(d) }

func (b *builder) seal() {
	b.t.Helper()
	sealed, err := b.batcher.Seal(b.now)
	if err != nil {
		b.t.Fatal(err)
	}
	b.checkpts = append(b.checkpts, sealed.Checkpoint)
}

func (b *builder) source() Source {
	return Source{SourceID: srcID, Origin: origin, Entries: b.entries, Checkpoints: b.checkpts}
}

func testKeyring(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, Keyring) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, Keyring{keyName: pub}
}

// TestVerifyStillGreenAfterSaltErasure is the WS4 crypto-shredding e2e: records
// carrying a subject's HMAC pseudonym are verified, the subject's salt is then
// erased (severing identity linkability), and verification stays fully green —
// pseudonyms live inside the hashed bytes, so records are never rewritten.
func TestVerifyStillGreenAfterSaltErasure(t *testing.T) {
	_, priv, keys := testKeyring(t)

	salts, err := pseudonym.Open(filepath.Join(t.TempDir(), "salts.json"))
	if err != nil {
		t.Fatal(err)
	}
	actor, err := salts.Pseudonym("alice@acme")
	if err != nil {
		t.Fatal(err)
	}

	b := newBuilder(t, priv)
	b.actor = actor
	for i := 0; i < 4; i++ {
		b.heartbeat(20)
		b.tick(60 * time.Second)
	}
	b.seal()

	if res := Verify(b.source(), keys, DefaultPolicy()); !res.Chain.Valid || !res.Checkpoints.Consistent {
		t.Fatalf("pre-erasure verification not green: chain=%+v checkpoints=%+v", res.Chain, res.Checkpoints)
	}

	// Erase the subject's salt: linkability is gone, records are untouched.
	if err := salts.Erase("alice@acme"); err != nil {
		t.Fatal(err)
	}
	if _, ok := salts.Lookup("alice@acme"); ok {
		t.Fatal("Lookup true after erasure")
	}

	res := Verify(b.source(), keys, DefaultPolicy())
	if !res.Chain.Valid {
		t.Fatalf("post-erasure chain invalid: %v", res.Chain.Err)
	}
	if res.Checkpoints.SignaturesValid != res.Checkpoints.Total || !res.Checkpoints.Consistent {
		t.Fatalf("post-erasure checkpoints not green: %+v", res.Checkpoints)
	}
	// The pseudonym is still literally present in the record bytes.
	if !bytesContainActor(b.entries, actor) {
		t.Fatal("pseudonym missing from records after erasure — records must never be rewritten")
	}
}

func bytesContainActor(entries []chain.Entry, actor string) bool {
	for _, e := range entries {
		if strings.Contains(string(e.Bytes), actor) {
			return true
		}
	}
	return false
}

func TestVerifyHappyPath(t *testing.T) {
	pub, priv, keys := testKeyring(t)
	_ = pub
	b := newBuilder(t, priv)
	for i := 0; i < 5; i++ {
		b.heartbeat(20)
		b.tick(60 * time.Second)
	}
	b.seal()

	res := Verify(b.source(), keys, DefaultPolicy())
	if !res.Chain.Valid {
		t.Fatalf("chain invalid: %v", res.Chain.Err)
	}
	if res.Checkpoints.Total != 1 || res.Checkpoints.SignaturesValid != 1 || res.Checkpoints.RootsValid != 1 {
		t.Fatalf("checkpoint check: %+v", res.Checkpoints)
	}
	if !res.Checkpoints.Consistent {
		t.Fatal("checkpoints should be consistent")
	}
	if !res.Continuity.Summary.WithinPolicy {
		t.Fatalf("continuity should be within policy: %+v", res.Continuity.Summary)
	}
	if res.Continuity.Summary.Observed != 5 {
		t.Fatalf("observed heartbeats = %d, want 5", res.Continuity.Summary.Observed)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
}

func TestVerifyConsistencyAcrossCheckpoints(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.seal() // size 2
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.seal() // size 4

	res := Verify(b.source(), keys, DefaultPolicy())
	if res.Checkpoints.Total != 2 || res.Checkpoints.RootsValid != 2 {
		t.Fatalf("checkpoint check: %+v", res.Checkpoints)
	}
	if !res.Checkpoints.Consistent {
		t.Fatal("append-only checkpoints must be consistent")
	}
}

func TestVerifyUnobservedWindow(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.tick(47 * time.Minute) // silence far beyond 3m
	b.heartbeat(10)
	b.seal()

	res := Verify(b.source(), keys, DefaultPolicy())
	if res.Continuity.Summary.WithinPolicy {
		t.Fatal("47m gap should breach policy")
	}
	if len(res.Continuity.Windows) != 1 || res.Continuity.Windows[0].Bounded {
		t.Fatalf("expected one unbounded window: %+v", res.Continuity.Windows)
	}
	if !hasFinding(res.Findings, "F-GAP-1") {
		t.Fatalf("expected F-GAP finding, got %+v", res.Findings)
	}
}

func TestVerifyBoundedWindowNoFinding(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.add(evAgentStopped, nil)
	b.tick(47 * time.Minute)
	b.add(evAgentStarted, nil)
	b.heartbeat(10)
	b.seal()

	res := Verify(b.source(), keys, DefaultPolicy())
	if len(res.Continuity.Windows) != 1 || !res.Continuity.Windows[0].Bounded {
		t.Fatalf("window should be bounded by stop/start: %+v", res.Continuity.Windows)
	}
	if hasFinding(res.Findings, "F-GAP-1") {
		t.Fatal("bounded window must not raise a gap finding")
	}
}

func TestVerifyTransportOutageReplay(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.add(evOutage, nil) // seq 2
	b.tick(8 * time.Minute)
	b.add("access.granted", nil) // buffered, seq 3
	b.add("access.revoked", nil) // buffered, seq 4
	b.add(evReplay, nil)         // seq 5
	b.seal()

	res := Verify(b.source(), keys, DefaultPolicy())
	if res.Transport.Outages != 1 {
		t.Fatalf("outages = %d, want 1", res.Transport.Outages)
	}
	if !res.Transport.ReplayCompleted {
		t.Fatal("replay should be marked complete")
	}
	if res.Transport.BufferedEvents != 2 {
		t.Fatalf("buffered = %d, want 2", res.Transport.BufferedEvents)
	}
	if res.Transport.LongestOutage < 8*time.Minute {
		t.Fatalf("longest outage = %s, want >= 8m", res.Transport.LongestOutage)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.tick(60 * time.Second)
	b.heartbeat(10)
	b.seal()
	src := b.source()
	src.Entries[0].Bytes = append([]byte(nil), src.Entries[0].Bytes...)
	src.Entries[0].Bytes[5] ^= 0xff // corrupt stored bytes

	res := Verify(src, keys, DefaultPolicy())
	if res.Chain.Valid {
		t.Fatal("tampered record should break the chain")
	}
	if !hasFinding(res.Findings, "F-CHAIN") {
		t.Fatalf("expected F-CHAIN finding, got %+v", res.Findings)
	}
}

func TestVerifyRejectsUnregisteredSigner(t *testing.T) {
	_, priv, _ := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(10)
	b.seal()
	// Keyring with a different key: the checkpoint signature won't verify.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res := Verify(b.source(), Keyring{keyName: otherPub}, DefaultPolicy())
	if res.Checkpoints.SignaturesValid != 0 {
		t.Fatalf("unregistered signer should not verify: %+v", res.Checkpoints)
	}
	if !hasFinding(res.Findings, "F-SIG") {
		t.Fatalf("expected F-SIG finding, got %+v", res.Findings)
	}
}

func TestVerifyClockDriftFinding(t *testing.T) {
	_, priv, keys := testKeyring(t)
	b := newBuilder(t, priv)
	b.heartbeat(2000) // 2s drift, over 1s policy
	b.seal()
	res := Verify(b.source(), keys, DefaultPolicy())
	if res.MaxClockDriftMS != 2000 {
		t.Fatalf("max drift = %d, want 2000", res.MaxClockDriftMS)
	}
	if !hasFinding(res.Findings, "F-CLOCK") {
		t.Fatalf("expected F-CLOCK finding, got %+v", res.Findings)
	}
}

func TestVerifyInputAttestation(t *testing.T) {
	_, priv, keys := testKeyring(t)

	build := func(lastDrift int64) SourceResult {
		b := newBuilder(t, priv)
		b.heartbeat(10)
		b.tick(60 * time.Second)
		b.heartbeat(lastDrift)
		b.seal()
		return Verify(b.source(), keys, DefaultPolicy())
	}

	a := build(20)
	if a.Inputs.RecordCount != 2 {
		t.Fatalf("record count = %d, want 2", a.Inputs.RecordCount)
	}
	if len(a.Inputs.CheckpointIDs) == 0 {
		t.Fatal("expected checkpoint ids when checkpoints are present")
	}

	// Deterministic across two runs on identical entries.
	if b := build(20); a.Inputs.InputDigest != b.Inputs.InputDigest {
		t.Fatalf("input digest not deterministic: %s vs %s", a.Inputs.InputDigest, b.Inputs.InputDigest)
	}

	// A single changed record byte changes the digest.
	if c := build(21); a.Inputs.InputDigest == c.Inputs.InputDigest {
		t.Fatal("input digest must change when a record byte changes")
	}
}

func hasFinding(fs []evidence.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}
