// Package keys generates, stores, and loads the two prooflog key types: a
// per-agent Ed25519 signing key and a per-org age X25519 recipient identity.
// Key types are kept strictly separate — one key, one purpose (REQ-C-11).
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"filippo.io/age"

	"github.com/arhuman/prooflog/internal/note"
)

const fileMode = 0o600

// AgentKey is a per-agent Ed25519 signing keypair with metadata. The private
// key stays on the host (REQ-C-11).
type AgentKey struct {
	Name    string
	Created time.Time
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// KeyID returns the C2SP 4-byte key ID for this signing key, shared with the
// note package (REQ-C-06).
func (k AgentKey) KeyID() [4]byte {
	return note.KeyID(k.Name, k.Public)
}

// KeyIDHex returns the hex encoding of the C2SP 4-byte key ID, for use in
// key-rotation/revocation event payloads and report findings (REQ-C-06).
func (k AgentKey) KeyIDHex() string {
	id := k.KeyID()
	return hex.EncodeToString(id[:])
}

type agentKeyFile struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created_at"`
	Alg     string    `json:"alg"`
	Public  string    `json:"public"`
	Private string    `json:"private"`
}

// GenerateAgentKey creates a fresh Ed25519 signing key named name (REQ-C-11).
func GenerateAgentKey(name string, now time.Time) (AgentKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return AgentKey{}, fmt.Errorf("keys: generate agent key: %w", err)
	}
	return AgentKey{Name: name, Created: now.UTC(), Public: pub, Private: priv}, nil
}

// SaveAgentKey writes the agent key to path with mode 0600 (REQ-C-11).
func SaveAgentKey(path string, k AgentKey) error {
	f := agentKeyFile{
		Name:    k.Name,
		Created: k.Created.UTC(),
		Alg:     "ed25519",
		Public:  base64.StdEncoding.EncodeToString(k.Public),
		Private: base64.StdEncoding.EncodeToString(k.Private),
	}
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("keys: marshal agent key: %w", err)
	}
	if err := os.WriteFile(path, b, fileMode); err != nil {
		return fmt.Errorf("keys: write agent key: %w", err)
	}
	return nil
}

// LoadAgentKey reads an agent key from path.
func LoadAgentKey(path string) (AgentKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return AgentKey{}, fmt.Errorf("keys: read agent key: %w", err)
	}
	var f agentKeyFile
	if err := json.Unmarshal(b, &f); err != nil {
		return AgentKey{}, fmt.Errorf("keys: parse agent key: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(f.Public)
	if err != nil {
		return AgentKey{}, fmt.Errorf("keys: decode public: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(f.Private)
	if err != nil {
		return AgentKey{}, fmt.Errorf("keys: decode private: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		return AgentKey{}, fmt.Errorf("keys: invalid ed25519 key sizes")
	}
	return AgentKey{
		Name:    f.Name,
		Created: f.Created,
		Public:  ed25519.PublicKey(pub),
		Private: ed25519.PrivateKey(priv),
	}, nil
}

// OrgKey is a per-org age X25519 identity with metadata. The private identity
// is output once for offline backup; only the recipient is distributed
// (REQ-C-08, REQ-C-11).
type OrgKey struct {
	Name     string
	Created  time.Time
	Identity *age.X25519Identity
}

// Recipient returns the public age recipient string for distribution.
func (k OrgKey) Recipient() string {
	return k.Identity.Recipient().String()
}

type orgKeyFile struct {
	Name     string    `json:"name"`
	Created  time.Time `json:"created_at"`
	Alg      string    `json:"alg"`
	Identity string    `json:"identity"`
}

// GenerateOrgKey creates a fresh age X25519 identity named name (REQ-C-08).
func GenerateOrgKey(name string, now time.Time) (OrgKey, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return OrgKey{}, fmt.Errorf("keys: generate org key: %w", err)
	}
	return OrgKey{Name: name, Created: now.UTC(), Identity: id}, nil
}

// SaveOrgKey writes the org identity to path with mode 0600 (REQ-C-11).
func SaveOrgKey(path string, k OrgKey) error {
	f := orgKeyFile{
		Name:     k.Name,
		Created:  k.Created.UTC(),
		Alg:      "age-x25519",
		Identity: k.Identity.String(),
	}
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("keys: marshal org key: %w", err)
	}
	if err := os.WriteFile(path, b, fileMode); err != nil {
		return fmt.Errorf("keys: write org key: %w", err)
	}
	return nil
}

// LoadOrgKey reads an org identity from path.
func LoadOrgKey(path string) (OrgKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return OrgKey{}, fmt.Errorf("keys: read org key: %w", err)
	}
	var f orgKeyFile
	if err := json.Unmarshal(b, &f); err != nil {
		return OrgKey{}, fmt.Errorf("keys: parse org key: %w", err)
	}
	id, err := age.ParseX25519Identity(f.Identity)
	if err != nil {
		return OrgKey{}, fmt.Errorf("keys: parse identity: %w", err)
	}
	return OrgKey{Name: f.Name, Created: f.Created, Identity: id}, nil
}
