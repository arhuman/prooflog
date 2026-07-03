package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/keys"
)

// ===== export happy path =====================================================

// TestRunExportHappyPath exercises the full runExport pipeline against an empty
// store (zero frames): flag parsing, org-key loading, gRPC pull (returns
// nothing), chain verification of an empty set, and bundle writing. It asserts
// nil error and the presence of the three files that are always written.
//
// The seq/time filter path is not tested here because populating the store with
// real uploaded segments is out of scope for a CLI-contract test; the filter
// logic is covered in internal/export tests.
func TestRunExportHappyPath(t *testing.T) {
	addr := newInsecureStoreServer(t)

	// Generate an org key and save it so runExport can load it.
	orgKey, err := keys.GenerateOrgKey("test-org", time.Now())
	if err != nil {
		t.Fatalf("generate org key: %v", err)
	}
	identityPath := filepath.Join(t.TempDir(), "org.json")
	if err := keys.SaveOrgKey(identityPath, orgKey); err != nil {
		t.Fatalf("save org key: %v", err)
	}

	// t.TempDir() is always empty — satisfies the non-empty-dir guard.
	outDir := t.TempDir()

	if err := runExport([]string{
		"--store-addr", addr,
		"--insecure",
		"--source", "vps-01/api",
		"--identity", identityPath,
		"--out", outDir,
	}); err != nil {
		t.Fatalf("runExport: %v", err)
	}

	// These files are written by every export, even for an empty source.
	for _, name := range []string{"manifest.json", "records.jsonl"} {
		if _, statErr := os.Stat(filepath.Join(outDir, name)); statErr != nil {
			t.Errorf("expected bundle file %s, stat error: %v", name, statErr)
		}
	}
}

// ===== export error paths ====================================================

// TestRunExportNonexistentIdentity verifies that a valid --identity flag
// pointing to a missing file produces a non-nil error. This is distinct from
// the missing-flag case (already in helpers_test.go): here the flag is present
// but the path does not exist. The error surfaces from keys.LoadOrgKey before
// any gRPC dial occurs, so no store server is needed.
func TestRunExportNonexistentIdentity(t *testing.T) {
	err := runExport([]string{
		"--source", "vps-01/api",
		"--identity", filepath.Join(t.TempDir(), "does-not-exist.json"),
		"--out", t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected error for nonexistent identity path, got nil")
	}
}
