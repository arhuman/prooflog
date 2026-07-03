package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestRunAssessExitsOnFindings(t *testing.T) {
	in := writeTemp(t, "signins.jsonl", strings.Join([]string{
		`{"createdDateTime":"2026-03-01T09:00:00Z","userPrincipalName":"a@x","activityDisplayName":"signin"}`,
		`{"createdDateTime":"2026-03-02T09:00:00Z","userPrincipalName":"b@x","activityDisplayName":"signin"}`,
	}, "\n"))
	out := filepath.Join(t.TempDir(), "assessment.md")
	err := runAssess([]string{
		"--input", in, "--profile", "idp-signin",
		"--org", "acme", "--period", "2026-01-01:2026-06-30", "--out", out,
	})
	if err == nil {
		t.Fatal("expected non-nil error (exit 1) from the coverage finding")
	}
	if !strings.Contains(err.Error(), "indicative finding") {
		t.Errorf("unexpected error: %v", err)
	}
	doc, rerr := os.ReadFile(out)
	if rerr != nil {
		t.Fatalf("read report: %v", rerr)
	}
	s := string(doc)
	if !strings.Contains(s, "TIER 0 — ASSESSMENT ONLY") {
		t.Error("report missing Tier 0 banner")
	}
	if !strings.Contains(s, "A-COVERAGE") {
		t.Error("report missing expected A-COVERAGE finding")
	}
}

func TestRunAssessCleanSequence(t *testing.T) {
	in := writeTemp(t, "clean.jsonl", strings.Join([]string{
		`{"source":"s","time":"2026-01-01T00:00:00Z","seq":1,"type":"deploy"}`,
		`{"source":"s","time":"2026-01-01T00:01:00Z","seq":2,"type":"deploy"}`,
		`{"source":"s","time":"2026-01-01T00:02:00Z","seq":3,"type":"deploy"}`,
	}, "\n"))
	out := filepath.Join(t.TempDir(), "clean.md")
	jsonOut := filepath.Join(t.TempDir(), "findings.json")
	err := runAssess([]string{"--input", in, "--profile", "generic", "--out", out, "--json", jsonOut})
	if err != nil {
		t.Fatalf("clean sequence should exit 0, got: %v", err)
	}
	fj, _ := os.ReadFile(jsonOut)
	if strings.TrimSpace(string(fj)) != "null" && strings.Contains(string(fj), "A-") {
		t.Errorf("clean run should have no findings, json: %s", fj)
	}
}

func TestRunAssessRequiresInput(t *testing.T) {
	if err := runAssess([]string{"--profile", "generic"}); err == nil {
		t.Error("expected error when no --input given")
	}
}

func TestRunAssessUnknownProfile(t *testing.T) {
	in := writeTemp(t, "x.jsonl", `{"source":"s","time":"2026-01-01T00:00:00Z","seq":1}`)
	if err := runAssess([]string{"--input", in, "--profile", "does-not-exist"}); err == nil {
		t.Error("expected error for unknown profile")
	}
}
