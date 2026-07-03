package verifier

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// SourceKey registers one source's signing identity with the verifier. The
// verifier holds only public keys — never private material (REQ-C-11).
type SourceKey struct {
	SourceID  string
	Origin    string
	KeyName   string
	PublicKey ed25519.PublicKey
}

// Registry maps source IDs to their registered signing keys (REQ-C-07 step 1).
// A source may register several keys over its lifetime as the agent rotates its
// signing key; every past public key stays registered so historical checkpoints
// keep verifying (REQ-C-11).
type Registry struct {
	bySource map[string][]SourceKey
}

type registryEntry struct {
	SourceID  string `json:"source_id"`
	Origin    string `json:"origin"`
	KeyName   string `json:"key_name"`
	PublicKey string `json:"public_key"`
}

type registryFile struct {
	Sources []registryEntry `json:"sources"`
}

// LoadRegistry reads a registered-keys JSON file (REQ-C-07, REQ-C-11). The
// sources array may hold several entries for the same source_id with distinct
// key_name values; all are accumulated so rotated sources verify cleanly.
func LoadRegistry(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("verifier: read registry: %w", err)
	}
	var f registryFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("verifier: parse registry: %w", err)
	}
	reg := &Registry{bySource: make(map[string][]SourceKey, len(f.Sources))}
	for _, s := range f.Sources {
		pub, err := base64.StdEncoding.DecodeString(s.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("verifier: decode public key for %s: %w", s.SourceID, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("verifier: bad public key size for %s", s.SourceID)
		}
		reg.bySource[s.SourceID] = append(reg.bySource[s.SourceID], SourceKey{
			SourceID:  s.SourceID,
			Origin:    s.Origin,
			KeyName:   s.KeyName,
			PublicKey: ed25519.PublicKey(pub),
		})
	}
	return reg, nil
}

// Source returns the most recently registered key for sourceID. All of a
// source's keys share the same origin, so callers needing only the Origin can
// use this; callers verifying signatures must use Keyring or SourceKeys to try
// every registered key (rotation).
func (r *Registry) Source(sourceID string) (SourceKey, bool) {
	keys := r.bySource[sourceID]
	if len(keys) == 0 {
		return SourceKey{}, false
	}
	return keys[len(keys)-1], true
}

// SourceKeys returns every registered key for sourceID in registration order,
// or nil when the source is unknown.
func (r *Registry) SourceKeys(sourceID string) []SourceKey {
	keys := r.bySource[sourceID]
	if len(keys) == 0 {
		return nil
	}
	out := make([]SourceKey, len(keys))
	copy(out, keys)
	return out
}

// Keyring returns a Keyring holding every registered public key for sourceID,
// keyed by key name. The offline engine matches checkpoints to keys by C2SP key
// id across the whole keyring, so a rotated source verifies cleanly (REQ-C-07).
func (r *Registry) Keyring(sourceID string) (Keyring, bool) {
	keys := r.bySource[sourceID]
	if len(keys) == 0 {
		return nil, false
	}
	kr := make(Keyring, len(keys))
	for _, sk := range keys {
		kr[sk.KeyName] = sk.PublicKey
	}
	return kr, true
}

// SourceIDs returns the distinct registered source IDs in sorted order. Used to
// iterate sources once regardless of how many keys each has registered.
func (r *Registry) SourceIDs() []string {
	out := make([]string, 0, len(r.bySource))
	for id := range r.bySource {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Sources returns all registered source keys, flattened across every source and
// every registered key.
func (r *Registry) Sources() []SourceKey {
	out := make([]SourceKey, 0, len(r.bySource))
	for _, keys := range r.bySource {
		out = append(out, keys...)
	}
	return out
}

// AppendKey appends a new {source_id, origin, key_name, public_key} entry to the
// registry file at path, creating the file if absent. It is the single-host
// convenience used by `prooflog key rotate --keys` to register a freshly rotated
// public key with a co-located verifier registry; an independent verifier's
// registry can only be updated by its own operator (REQ-C-11).
func AppendKey(path string, sk SourceKey) error {
	var f registryFile
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &f); err != nil {
			return fmt.Errorf("verifier: parse registry: %w", err)
		}
	case os.IsNotExist(err):
		// Fresh registry.
	default:
		return fmt.Errorf("verifier: read registry: %w", err)
	}
	f.Sources = append(f.Sources, registryEntry{
		SourceID:  sk.SourceID,
		Origin:    sk.Origin,
		KeyName:   sk.KeyName,
		PublicKey: base64.StdEncoding.EncodeToString(sk.PublicKey),
	})
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("verifier: marshal registry: %w", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("verifier: write registry: %w", err)
	}
	return nil
}
