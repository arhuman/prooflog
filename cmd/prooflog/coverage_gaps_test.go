package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestRunVerifyWithPeriod exercises the `if period != ""` branch inside
// printVerifySummary that prints the reporting window.
func TestRunVerifyWithPeriod(t *testing.T) {
	dir := t.TempDir()
	buildCleanSpool(t, dir)

	err := runVerify([]string{
		"--spool", dir,
		"--period", "2026-07-01:2026-07-04",
	})
	if err != nil {
		t.Fatalf("expected nil for clean spool with period, got %v", err)
	}
}

// TestRunVerifyWithEmptyCheckpoints exercises the checkpoints-directory loading
// branch in gatherResult without requiring real checkpoint files.
func TestRunVerifyWithEmptyCheckpoints(t *testing.T) {
	spoolDir := t.TempDir()
	buildCleanSpool(t, spoolDir)
	checkDir := t.TempDir() // empty: no checkpoints

	err := runVerify([]string{
		"--spool", spoolDir,
		"--checkpoints", checkDir,
	})
	if err != nil {
		t.Fatalf("expected nil for clean spool with empty checkpoints dir, got %v", err)
	}
}

// TestRunVerifyWithEmptyAnchors exercises the anchors-directory loading branch
// in gatherResult.
func TestRunVerifyWithEmptyAnchors(t *testing.T) {
	spoolDir := t.TempDir()
	buildCleanSpool(t, spoolDir)
	anchorDir := t.TempDir() // empty: no anchors

	err := runVerify([]string{
		"--spool", spoolDir,
		"--anchors", anchorDir,
	})
	if err != nil {
		t.Fatalf("expected nil for clean spool with empty anchors dir, got %v", err)
	}
}

// TestRunReportToStdout exercises the path where no --out flag is given and
// the report is written to stdout; we redirect stdout to /dev/null to keep the
// test output clean.
func TestRunReportToStdout(t *testing.T) {
	spoolDir := t.TempDir()
	buildCleanSpool(t, spoolDir)

	// Redirect stdout temporarily so the markdown does not clutter test output.
	orig := os.Stdout
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	os.Stdout = devNull
	defer func() {
		os.Stdout = orig
		_ = devNull.Close()
	}()

	if err := runReport([]string{"--spool", spoolDir}); err != nil {
		t.Fatalf("runReport to stdout: %v", err)
	}
}

// TestRunActorIDMissingActor covers the NArg() != 1 branch in actorArg when
// --salts is set but no actor identity is supplied.
func TestRunActorIDMissingActor(t *testing.T) {
	saltsPath := filepath.Join(t.TempDir(), "salts.json")
	err := runActor([]string{"id", "--salts", saltsPath})
	if err == nil {
		t.Fatal("expected error when actor argument is missing, got nil")
	}
}

// TestRunActorEraseMissingActor covers the NArg() != 1 branch in actorArg
// for the erase subcommand.
func TestRunActorEraseMissingActor(t *testing.T) {
	saltsPath := filepath.Join(t.TempDir(), "salts.json")
	err := runActor([]string{"erase", "--salts", saltsPath})
	if err == nil {
		t.Fatal("expected error when actor argument is missing for erase, got nil")
	}
}

// TestGatherResultWithSourceOverride exercises the `if o.sourceID != "" {
// sourceID = o.sourceID }` path in gatherResult.
func TestGatherResultWithSourceOverride(t *testing.T) {
	dir := t.TempDir()
	buildCleanSpool(t, dir)

	res, sourceID, err := gatherResult(context.Background(), verifyOpts{
		spoolDir: dir,
		sourceID: "my-override-id",
	})
	if err != nil {
		t.Fatalf("gatherResult: %v", err)
	}
	if sourceID != "my-override-id" {
		t.Errorf("sourceID = %q, want %q", sourceID, "my-override-id")
	}
	if !res.Chain.Valid {
		t.Fatalf("chain must be valid: %v", res.Chain.Err)
	}
}
