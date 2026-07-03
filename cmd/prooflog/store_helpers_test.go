package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/store"
)

// ---- loadRetentionPolicy ----------------------------------------------------

// TestLoadRetentionPolicyNoFile checks the common path: no policy file is
// given so the shorthand --retention duration is used to synthesise a policy.
func TestLoadRetentionPolicyNoFile(t *testing.T) {
	p, err := loadRetentionPolicy("", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.DefaultDays != 30 {
		t.Errorf("DefaultDays = %d, want 30", p.DefaultDays)
	}
}

// TestLoadRetentionPolicyValidFile checks that a well-formed JSON policy file
// is read and parsed correctly.
func TestLoadRetentionPolicyValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	content, _ := json.Marshal(store.RetentionPolicy{DefaultDays: 90})
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	p, err := loadRetentionPolicy(path, 365*24*time.Hour) // shorthand ignored when file given
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.DefaultDays != 90 {
		t.Errorf("DefaultDays = %d, want 90", p.DefaultDays)
	}
}

// TestLoadRetentionPolicyMissingFile checks that a missing file is reported.
func TestLoadRetentionPolicyMissingFile(t *testing.T) {
	_, err := loadRetentionPolicy("/nonexistent/policy.json", 0)
	if err == nil {
		t.Fatal("expected error for missing policy file, got nil")
	}
}

// TestLoadRetentionPolicyInvalidJSON checks that malformed JSON is rejected.
func TestLoadRetentionPolicyInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	_, err := loadRetentionPolicy(path, 0)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}
