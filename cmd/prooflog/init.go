package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arhuman/prooflog/internal/agent"
	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/version"
)

// runInit generates the org age identity and per-agent signing key, then writes
// a config skeleton. The org identity is printed ONCE for offline backup and is
// never persisted or uploaded (REQ-C-11, architecture §4.5).
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory for keys and config")
	org := fs.String("org", "", "organization name (required)")
	sourceID := fs.String("source-id", "", "source identity, e.g. vps-01/api (required)")
	agentName := fs.String("agent-name", "", "signing key name (default: sanitized source-id)")
	httpAddr := fs.String("http-addr", "127.0.0.1:9600", "local ingest HTTP address")
	storeAddr := fs.String("store-addr", "127.0.0.1:9700", "central store gRPC address")
	verifierAddr := fs.String("verifier-addr", "", "verifier gRPC address (optional)")
	keyID := fs.String("key-id", "", "recipient key id label (default: org-<org>-<year>-1)")
	sealMaxRecords := fs.Int("seal-max-records", 256, "records per segment before sealing")
	sealMaxAge := fs.Duration("seal-max-age", 60*time.Second, "max age before sealing a partial segment")
	heartbeatInterval := fs.Duration("heartbeat-interval", 60*time.Second, "heartbeat interval")
	storeLocality := fs.String("store-locality", "", "operator-declared store jurisdiction (e.g. CH); recorded, not proven")
	verifierLocality := fs.String("verifier-locality", "", "operator-declared verifier jurisdiction (e.g. EU/DE); recorded, not proven")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *org == "" || *sourceID == "" {
		return fmt.Errorf("--org and --source-id are required")
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	name := *agentName
	if name == "" {
		name = sanitize(*sourceID)
	}
	now := time.Now()

	agentKey, err := keys.GenerateAgentKey(name, now)
	if err != nil {
		return err
	}
	agentKeyPath := filepath.Join(*dir, "agent.key")
	if err := keys.SaveAgentKey(agentKeyPath, agentKey); err != nil {
		return err
	}

	orgKey, err := keys.GenerateOrgKey(*org, now)
	if err != nil {
		return err
	}

	kid := *keyID
	if kid == "" {
		kid = fmt.Sprintf("org-%s-%d-1", *org, now.Year())
	}

	cfg := agent.Config{
		SourceID:          *sourceID,
		Org:               *org,
		AgentName:         name,
		Version:           version.Version,
		SpoolDir:          filepath.Join(*dir, "spool"),
		AgentKeyPath:      agentKeyPath,
		SaltStorePath:     filepath.Join(*dir, "salts.json"),
		OrgRecipient:      orgKey.Recipient(),
		KeyID:             kid,
		HTTPAddr:          *httpAddr,
		StoreAddr:         *storeAddr,
		VerifierAddr:      *verifierAddr,
		HeartbeatInterval: agent.Duration(*heartbeatInterval),
		SealMaxRecords:    *sealMaxRecords,
		SealMaxAge:        agent.Duration(*sealMaxAge),
		SpoolPolicy:       "block",
		StoreLocality:     *storeLocality,
		VerifierLocality:  *verifierLocality,
		TLS:               api.TLSConfig{Insecure: true},
	}
	cfgPath := filepath.Join(*dir, "config.json")
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	keysPath := filepath.Join(*dir, "verifier-keys.json")
	if err := writeVerifierKeys(keysPath, cfg, agentKey); err != nil {
		return err
	}

	printInitSummary(cfgPath, agentKeyPath, keysPath, cfg.SaltStorePath, orgKey)
	fmt.Fprintf(os.Stderr,
		"note: the generated config uses plaintext transport (\"insecure\": true); set the tls section for production.\n")
	return nil
}

// writeVerifierKeys writes the public registration the verifier needs to verify
// this source's checkpoint signatures. Only the public key is emitted — private
// signing material never leaves the host (REQ-C-11).
func writeVerifierKeys(path string, cfg agent.Config, agentKey keys.AgentKey) error {
	reg := map[string]any{
		"sources": []map[string]string{{
			"source_id":  cfg.SourceID,
			"origin":     cfg.Origin(),
			"key_name":   cfg.AgentName,
			"public_key": base64.StdEncoding.EncodeToString(agentKey.Public),
		}},
	}
	b, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal verifier keys: %w", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write verifier keys: %w", err)
	}
	return nil
}

func printInitSummary(cfgPath, agentKeyPath, keysPath, saltPath string, orgKey keys.OrgKey) {
	fmt.Printf("prooflog initialized\n\n")
	fmt.Printf("  config:        %s\n", cfgPath)
	fmt.Printf("  agent key:     %s (0600, keep on this host)\n", agentKeyPath)
	fmt.Printf("  salt store:    %s (0600, re-links pseudonyms to identities — exclude from cross-border backups)\n", saltPath)
	fmt.Printf("  verifier keys: %s (public, give to the verifier)\n", keysPath)
	fmt.Printf("  org recipient (public, in config):\n    %s\n\n", orgKey.Recipient())
	fmt.Printf("========================================================================\n")
	fmt.Printf(" BACK UP THIS ORG IDENTITY NOW — IT IS SHOWN ONCE AND NEVER STORED.\n")
	fmt.Printf(" It is the ONLY key that can decrypt event payloads. Store it offline.\n")
	fmt.Printf("========================================================================\n\n")
	fmt.Printf("  %s\n\n", orgKey.Identity.String())
}

func sanitize(s string) string {
	return strings.NewReplacer("/", "-", " ", "-").Replace(s)
}
