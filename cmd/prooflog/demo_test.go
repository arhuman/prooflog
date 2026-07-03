package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/merkle"
	"github.com/arhuman/prooflog/internal/note"
	"github.com/arhuman/prooflog/internal/spool"
)

// buildChainedSpool writes n properly-chained heartbeat records to dir so a
// pristine verify is clean and each mutation can be shown in isolation.
func buildChainedSpool(t *testing.T, dir string, n int) {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	prev := envelope.ZeroHash
	for i := 1; i <= n; i++ {
		ts := envelope.FormatTime(base.Add(time.Duration(i) * time.Second))
		rec := envelope.Record{
			Version:      envelope.Version,
			SourceID:     "vps-01/api",
			Seq:          uint64(i),
			EventType:    "system.heartbeat",
			EventTime:    ts,
			IngestTime:   ts,
			PayloadClear: []byte(`{"health":{"clock_drift_ms":10}}`),
			PrevHash:     prev,
		}
		if err := rec.Serialize(); err != nil {
			t.Fatal(err)
		}
		if err := sp.Append(rec); err != nil {
			t.Fatal(err)
		}
		prev = rec.HashHex()
	}
	_ = sp.Close()
}

func hasFinding(t *testing.T, spoolDir, checkpointsDir, keysPath, id string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, _, err := gatherResult(ctx, verifyOpts{
		spoolDir:       spoolDir,
		checkpointsDir: checkpointsDir,
		keysPath:       keysPath,
	})
	if err != nil {
		t.Fatalf("gatherResult: %v", err)
	}
	for _, f := range res.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

// TestTamperModifyEvent asserts flipping a byte in a non-last record and
// recomputing its frame hash breaks the chain link (F-CHAIN).
func TestTamperModifyEvent(t *testing.T) {
	dir := t.TempDir()
	buildChainedSpool(t, dir, 3)

	if err := runVerify([]string{"--spool", dir}); err != nil {
		t.Fatalf("pristine spool should verify clean, got %v", err)
	}
	if _, err := tamperModifyEvent(dir); err != nil {
		t.Fatalf("tamperModifyEvent: %v", err)
	}
	if err := runVerify([]string{"--spool", dir}); err == nil {
		t.Fatal("expected runVerify to fail after modifying an event")
	}
	if !hasFinding(t, dir, "", "", "F-CHAIN") {
		t.Fatal("expected F-CHAIN after modifying an event")
	}
}

// TestTamperDeleteSegment asserts dropping a middle block of records opens a
// sequence gap that breaks the chain (F-CHAIN).
func TestTamperDeleteSegment(t *testing.T) {
	dir := t.TempDir()
	buildChainedSpool(t, dir, 6)

	if err := runVerify([]string{"--spool", dir}); err != nil {
		t.Fatalf("pristine spool should verify clean, got %v", err)
	}
	if _, err := tamperDeleteSegment(dir); err != nil {
		t.Fatalf("tamperDeleteSegment: %v", err)
	}
	if err := runVerify([]string{"--spool", dir}); err == nil {
		t.Fatal("expected runVerify to fail after deleting a segment")
	}
	if !hasFinding(t, dir, "", "", "F-CHAIN") {
		t.Fatal("expected F-CHAIN after deleting a segment")
	}
}

// TestTamperRewriteCheckpoint asserts corrupting a signed checkpoint body makes
// its signature fail (F-SIG) and breaks append-only consistency (F-FORK).
func TestTamperRewriteCheckpoint(t *testing.T) {
	dir := t.TempDir()
	spoolDir := filepath.Join(dir, "spool")
	cpDir := filepath.Join(dir, "verifier-data")
	keysPath := filepath.Join(dir, "verifier-keys.json")
	buildChainedSpool(t, spoolDir, 2)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyName = "acme-vps-01-api"
	cp := note.Checkpoint{Origin: "acme vps-01/api", Size: 1}
	signed, err := note.Sign(cp.Marshal(), keyName, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	notesPath := checkpointNotesFile(cpDir, "vps-01/api")
	line, _ := json.Marshal(signed)
	if err := os.WriteFile(notesPath, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, keysPath, keyName, pub)

	if _, err := tamperRewriteCheckpoint(notesPath); err != nil {
		t.Fatalf("tamperRewriteCheckpoint: %v", err)
	}
	if !hasFinding(t, spoolDir, cpDir, keysPath, "F-SIG") {
		t.Fatal("expected F-SIG after rewriting a checkpoint")
	}
	if !hasFinding(t, spoolDir, cpDir, keysPath, "F-FORK") {
		t.Fatal("expected F-FORK after rewriting a checkpoint")
	}
}

// TestTamperTruncateLog asserts that dropping the tail below the largest
// checkpoint's committed size leaves the on-disk chain internally valid (no
// F-CHAIN) yet the independent signed checkpoint still catches the loss
// (F-FORK), because its Merkle root cannot be recomputed from the short prefix.
func TestTamperTruncateLog(t *testing.T) {
	dir := t.TempDir()
	spoolDir := filepath.Join(dir, "spool")
	cpDir := filepath.Join(dir, "verifier-data")
	keysPath := filepath.Join(dir, "verifier-keys.json")
	const n = 4
	buildChainedSpool(t, spoolDir, n)

	// A checkpoint committing to all n records, with the real Merkle root so the
	// pristine state verifies clean and consistent.
	files, err := segmentFiles(spoolDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("want one spool segment, got %v (err %v)", files, err)
	}
	frames, err := readFrames(files[0])
	if err != nil {
		t.Fatal(err)
	}
	entries := make([][]byte, len(frames))
	for i, fr := range frames {
		entries[i] = fr.body
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const keyName = "acme-vps-01-api"
	cp := note.Checkpoint{Origin: "acme vps-01/api", Size: n, Hash: merkle.RootFromEntries(entries)}
	signed, err := note.Sign(cp.Marshal(), keyName, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	notesPath := checkpointNotesFile(cpDir, "vps-01/api")
	line, _ := json.Marshal(signed)
	if err := os.WriteFile(notesPath, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, keysPath, keyName, pub)

	if hasFinding(t, spoolDir, cpDir, keysPath, "F-FORK") {
		t.Fatal("pristine evidence should have no F-FORK before truncation")
	}
	if _, err := tamperTruncateLog(spoolDir, notesPath); err != nil {
		t.Fatalf("tamperTruncateLog: %v", err)
	}
	if !hasFinding(t, spoolDir, cpDir, keysPath, "F-FORK") {
		t.Fatal("expected F-FORK after truncating below the checkpoint size")
	}
	if hasFinding(t, spoolDir, cpDir, keysPath, "F-CHAIN") {
		t.Fatal("truncation keeps a valid prefix chain; F-CHAIN should not fire")
	}
}

func writeRegistry(t *testing.T, path, keyName string, pub ed25519.PublicKey) {
	t.Helper()
	reg := map[string]any{
		"sources": []map[string]any{{
			"source_id":  "vps-01/api",
			"origin":     "acme vps-01/api",
			"key_name":   keyName,
			"public_key": base64.StdEncoding.EncodeToString(pub),
		}},
	}
	b, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestFlipHelpers covers the byte-mutation helpers directly.
func TestFlipHelpers(t *testing.T) {
	b := []byte(`{"event_time":"2026-07-04T12:00:00Z"}`)
	if !flipField(b, `"event_time":"`) {
		t.Fatal("flipField should find event_time")
	}
	if b[len(`{"event_time":"`)] != '3' {
		t.Fatalf("expected leading digit flipped to 3, got %q", b)
	}
	if flipField([]byte(`{}`), `"event_time":"`) {
		t.Fatal("flipField should fail when field absent")
	}

	body := []byte("acme vps-01/api\n1\nroot")
	if !flipFirstLetter(body) {
		t.Fatal("flipFirstLetter should mutate a letter")
	}
	if body[0] != 'b' {
		t.Fatalf("expected 'a'->'b', got %q", body[0])
	}
	if flipFirstLetter([]byte("123 456")) {
		t.Fatal("flipFirstLetter should fail with no letters")
	}
}

// TestRunDemoUnknownMode rejects an unknown positional mode.
func TestRunDemoUnknownMode(t *testing.T) {
	if err := runDemo([]string{"bogus"}); err == nil {
		t.Fatal("expected error for unknown demo mode")
	}
}

// TestDemoEndToEnd runs the full subprocess orchestration against the real
// binary. It is skipped in -short mode and unless PROOFLOG_DEMO_E2E is set,
// because make test does not pass -short and the run binds fixed loopback ports.
func TestDemoEndToEnd(t *testing.T) {
	if testing.Short() || os.Getenv("PROOFLOG_DEMO_E2E") == "" {
		t.Skip("set PROOFLOG_DEMO_E2E=1 (and drop -short) to run the demo orchestration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "prooflog")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	ws := t.TempDir()
	cmd := exec.CommandContext(ctx, bin, "demo", "tamper", "--dir", ws, "--keep")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("demo tamper: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "4 tampering attempts, 4 detected") {
		t.Fatalf("demo output missing detection summary:\n%s", out)
	}
}
