package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunReportToFile exercises the full report generation path: a clean spool
// is verified, the Markdown report is written to a temp file, and the file is
// checked for required top-level structure.
func TestRunReportToFile(t *testing.T) {
	spoolDir := t.TempDir()
	buildCleanSpool(t, spoolDir)

	outPath := filepath.Join(t.TempDir(), "report.md")
	err := runReport([]string{
		"--spool", spoolDir,
		"--org", "acme",
		"--out", outPath,
	})
	if err != nil {
		t.Fatalf("runReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	body := string(data)

	for _, want := range []string{
		"# Prooflog — Continuity & Integrity Report",
		"## 1. Verdict",
		"Report signature: not configured",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

// TestRunReportBadPeriod ensures an invalid --period flag is rejected before
// any work is done.
func TestRunReportBadPeriod(t *testing.T) {
	spoolDir := t.TempDir()
	buildCleanSpool(t, spoolDir)

	err := runReport([]string{
		"--spool", spoolDir,
		"--period", "bad-value",
	})
	if err == nil {
		t.Fatal("expected error for malformed --period, got nil")
	}
}

// TestRunReportNoSource ensures that calling runReport with neither --spool nor
// --store-addr returns an error.
func TestRunReportNoSource(t *testing.T) {
	if err := runReport([]string{}); err == nil {
		t.Fatal("expected error when no source is specified, got nil")
	}
}

// TestReportFileName verifies the pure helper that derives the file name to
// embed in the signed report footer.
func TestReportFileName(t *testing.T) {
	tests := []struct {
		out  string
		want string
	}{
		{"", "<report.md>"},
		{"/path/to/my-report.md", "my-report.md"},
		{"report.md", "report.md"},
	}
	for _, tt := range tests {
		got := reportFileName(tt.out)
		if got != tt.want {
			t.Errorf("reportFileName(%q) = %q, want %q", tt.out, got, tt.want)
		}
	}
}
