package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/version"
)

func TestReproduceCommand(t *testing.T) {
	got := reproduceCommand(verifyOpts{
		spoolDir:       "./demo/spool",
		checkpointsDir: "./demo/verifier-data",
		keysPath:       "./demo/verifier-keys.json",
	}, "2026-06-30:2026-07-03")
	for _, want := range []string{
		"prooflog verify",
		"--spool ./demo/spool",
		"--checkpoints ./demo/verifier-data",
		"--keys ./demo/verifier-keys.json",
		"--period 2026-06-30:2026-07-03",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("reproduce command missing %q:\n%s", want, got)
		}
	}
}

func TestAppendSignatureRoundTrip(t *testing.T) {
	key, err := keys.GenerateAgentKey("vps-01-api", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "agent.key")
	if err := keys.SaveAgentKey(keyPath, key); err != nil {
		t.Fatal(err)
	}

	body := []byte("# Report\n\nbody line\n")
	signed, err := appendSignature(body, &key, "report.md", version.Version, binarySelfHash())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signed), "Report signed by: vps-01-api") {
		t.Fatalf("signed footer missing signer:\n%s", signed)
	}
	reportPath := filepath.Join(dir, "report.md")
	if err := os.WriteFile(reportPath, signed, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runReportVerify([]string{"--verify-key", keyPath, reportPath}); err != nil {
		t.Fatalf("valid signature must verify: %v", err)
	}

	// Tamper with the body: verification must fail.
	tampered := strings.Replace(string(signed), "body line", "body LINE", 1)
	if err := os.WriteFile(reportPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runReportVerify([]string{"--verify-key", keyPath, reportPath}); err == nil {
		t.Fatal("tampered report must fail verification")
	}
}

func TestAppendSignatureUnsigned(t *testing.T) {
	out, err := appendSignature([]byte("# Report\n"), nil, "report.md", version.Version, binarySelfHash())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "Report signature: not configured") {
		t.Fatalf("unsigned report must state not configured:\n%s", out)
	}
}
