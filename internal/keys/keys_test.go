package keys

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/note"
)

func TestAgentKeyRoundTripAndMode(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	k, err := GenerateAgentKey("vps-01-api", now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent.key")
	if err := SaveAgentKey(path, k); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("agent.key mode = %o, want 600", perm)
	}
	loaded, err := LoadAgentKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != k.Name || !loaded.Created.Equal(k.Created) {
		t.Fatal("metadata not preserved")
	}
	if !loaded.Public.Equal(k.Public) || !loaded.Private.Equal(k.Private) {
		t.Fatal("key material not preserved")
	}
}

func TestAgentKeyIDMatchesNote(t *testing.T) {
	t.Parallel()
	k, err := GenerateAgentKey("vps-01-api", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if k.KeyID() != note.KeyID(k.Name, k.Public) {
		t.Fatal("KeyID must match note.KeyID derivation")
	}
}

func TestAgentKeySignsVerifiably(t *testing.T) {
	t.Parallel()
	k, err := GenerateAgentKey("k", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("evidence")
	sig := ed25519.Sign(k.Private, msg)
	if !ed25519.Verify(k.Public, msg, sig) {
		t.Fatal("agent key does not sign/verify")
	}
}

func TestOrgKeyRoundTripAndMode(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	k, err := GenerateOrgKey("org-acme-2026-1", now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "org.key")
	if err := SaveOrgKey(path, k); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("org.key mode = %o, want 600", perm)
	}
	loaded, err := LoadOrgKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != k.Name {
		t.Fatal("org name not preserved")
	}
	if loaded.Recipient() != k.Recipient() {
		t.Fatal("recipient not preserved")
	}
	if loaded.Identity.String() != k.Identity.String() {
		t.Fatal("identity not preserved")
	}
}

func TestKeyTypesAreDistinct(t *testing.T) {
	t.Parallel()
	// One key, one purpose (REQ-C-11): recipient strings and signing keys are
	// structurally different namespaces.
	org, _ := GenerateOrgKey("org", time.Now())
	if got := org.Recipient(); len(got) < 4 || got[:4] != "age1" {
		t.Fatalf("org recipient not an age recipient: %q", got)
	}
}
