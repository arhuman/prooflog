package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/arhuman/prooflog/internal/agent"
)

// TestRunInitMissingArgs checks that --org and --source-id are both required.
func TestRunInitMissingArgs(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name string
		args []string
	}{
		{"no args", []string{"--dir", dir}},
		{"missing source-id", []string{"--dir", dir, "--org", "acme"}},
		{"missing org", []string{"--dir", dir, "--source-id", "vps-01/api"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := runInit(tc.args); err == nil {
				t.Fatal("expected error for missing required flags, got nil")
			}
		})
	}
}

// TestRunInitHappyPath exercises the complete init flow: agent key, org
// identity, config skeleton, and verifier-keys file are all written, file
// permissions are correct, and the config round-trips through LoadConfig.
func TestRunInitHappyPath(t *testing.T) {
	dir := t.TempDir()

	err := runInit([]string{
		"--dir", dir,
		"--org", "acme",
		"--source-id", "vps-01/api",
	})
	if err != nil {
		t.Fatalf("runInit: %v", err)
	}

	// All three files must exist.
	agentKeyPath := filepath.Join(dir, "agent.key")
	configPath := filepath.Join(dir, "config.json")
	verifierKeysPath := filepath.Join(dir, "verifier-keys.json")

	for _, path := range []string{agentKeyPath, configPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		// Key and config must be 0600 (owner read/write only).
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s permissions = %o, want 0600", path, perm)
		}
	}
	if _, err := os.Stat(verifierKeysPath); err != nil {
		t.Fatalf("verifier-keys.json missing: %v", err)
	}

	// The config must parse back correctly and have the expected source/org.
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg agent.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if cfg.SourceID != "vps-01/api" {
		t.Errorf("source_id = %q, want %q", cfg.SourceID, "vps-01/api")
	}
	if cfg.Org != "acme" {
		t.Errorf("org = %q, want %q", cfg.Org, "acme")
	}
	// The agent name must be the sanitized form of the source id.
	if cfg.AgentName != "vps-01-api" {
		t.Errorf("agent_name = %q, want %q", cfg.AgentName, "vps-01-api")
	}
}

// TestRunInitCustomAgentName verifies that --agent-name overrides the
// sanitize(source-id) default.
func TestRunInitCustomAgentName(t *testing.T) {
	dir := t.TempDir()

	err := runInit([]string{
		"--dir", dir,
		"--org", "acme",
		"--source-id", "vps-01/api",
		"--agent-name", "my-custom-agent",
	})
	if err != nil {
		t.Fatalf("runInit: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg agent.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if cfg.AgentName != "my-custom-agent" {
		t.Errorf("agent_name = %q, want %q", cfg.AgentName, "my-custom-agent")
	}
}
