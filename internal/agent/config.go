package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/spool"
	"github.com/arhuman/prooflog/internal/version"
)

// Duration is a time.Duration that marshals to/from a Go duration string in
// JSON (e.g. "60s"), keeping the config file human-editable.
type Duration time.Duration

// MarshalJSON renders the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON parses a duration string.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("agent: duration: %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("agent: duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// Config is the agent daemon configuration. It is written by `prooflog init`
// and read at startup. JSON (stdlib) is used instead of YAML to avoid a new
// dependency: the file is small and machine-generated.
type Config struct {
	// SourceID is the per-source identity, e.g. "vps-01/api".
	SourceID string `json:"source_id"`
	// Org is the organization name, used to build the checkpoint origin.
	Org string `json:"org"`
	// AgentName is the signing key name used in checkpoint signatures.
	AgentName string `json:"agent_name"`
	// Version is the agent version string embedded in heartbeats.
	Version string `json:"version"`

	SpoolDir     string `json:"spool_dir"`
	AgentKeyPath string `json:"agent_key"`
	// SaltStorePath holds the per-subject HMAC salts that map actor identities
	// to pseudonyms (WS4). It re-links pseudonyms to people, so it is sensitive
	// and erasable; default: salts.json beside the agent key.
	SaltStorePath string `json:"salt_store,omitempty"`
	// OrgRecipient is the public age recipient events are encrypted to. It is
	// used when Recipients is empty (the documented single-org-key default).
	OrgRecipient string `json:"org_recipient"`
	// Recipients, when non-empty, supersedes OrgRecipient: events are sealed to
	// every listed age recipient (interface-ready for per-subject payload keys).
	Recipients []string `json:"recipients,omitempty"`
	// KeyID labels the recipient key inside each record (REQ-C-11).
	KeyID string `json:"key_id"`

	HTTPAddr     string `json:"http_addr"`
	StoreAddr    string `json:"store_addr"`
	VerifierAddr string `json:"verifier_addr"`

	HeartbeatInterval Duration `json:"heartbeat_interval"`
	SealMaxRecords    int      `json:"seal_max_records"`
	SealMaxAge        Duration `json:"seal_max_age"`

	SpoolThresholdBytes uint64 `json:"spool_threshold_bytes"`
	// SpoolPolicy is "block" (default) or "drop-oldest" (REQ-E-09).
	SpoolPolicy string `json:"spool_policy"`

	// StoreLocality and VerifierLocality are operator-declared jurisdictions
	// recorded for chain-of-custody documentation; freeform, not validated.
	StoreLocality    string `json:"store_locality,omitempty"`
	VerifierLocality string `json:"verifier_locality,omitempty"`

	TLS api.TLSConfig `json:"tls"`
}

// DefaultConfig returns a config with the documented defaults applied.
func DefaultConfig() Config {
	return Config{
		Version:           version.Version,
		HTTPAddr:          "127.0.0.1:9600",
		StoreAddr:         "127.0.0.1:9700",
		HeartbeatInterval: Duration(60 * time.Second),
		SealMaxRecords:    256,
		SealMaxAge:        Duration(60 * time.Second),
		SpoolPolicy:       "block",
		// TLS defaults to the zero value (secure): the runtime default applied
		// when a loaded config omits the tls section must not silently run
		// plaintext. Insecure transport is an explicit opt-in only (REQ-E-04).
	}
}

// LoadConfig reads a JSON config from path and applies defaults for zero fields.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("agent: read config: %w", err)
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("agent: parse config: %w", err)
	}
	if cfg.SaltStorePath == "" && cfg.AgentKeyPath != "" {
		cfg.SaltStorePath = filepath.Join(filepath.Dir(cfg.AgentKeyPath), "salts.json")
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.SourceID == "" {
		return fmt.Errorf("agent: config missing source_id")
	}
	if c.Org == "" {
		return fmt.Errorf("agent: config missing org")
	}
	if c.SpoolDir == "" {
		return fmt.Errorf("agent: config missing spool_dir")
	}
	if c.AgentKeyPath == "" {
		return fmt.Errorf("agent: config missing agent_key")
	}
	if c.OrgRecipient == "" {
		return fmt.Errorf("agent: config missing org_recipient")
	}
	return nil
}

// Origin builds the checkpoint origin line "prooflog/<org>/<source_id>".
func (c Config) Origin() string {
	return "prooflog/" + c.Org + "/" + c.SourceID
}

func (c Config) spoolPolicy() spool.Policy {
	if c.SpoolPolicy == "drop-oldest" {
		return spool.DropOldest
	}
	return spool.Block
}
