package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func genPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func writeRegistry(t *testing.T, path string, entries ...registryEntry) {
	t.Helper()
	b, err := json.MarshalIndent(registryFile{Sources: entries}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func entry(sourceID, keyName string, pub ed25519.PublicKey) registryEntry {
	return registryEntry{
		SourceID:  sourceID,
		Origin:    origin,
		KeyName:   keyName,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
}

// TestRegistryMultiKeyLoad proves several keys for one source_id accumulate and
// that Keyring returns them all, Source returns the most recent, and SourceIDs
// deduplicates.
func TestRegistryMultiKeyLoad(t *testing.T) {
	pubA, pubB := genPub(t), genPub(t)
	path := filepath.Join(t.TempDir(), "keys.json")
	writeRegistry(t, path,
		entry(srcID, "vps-01-api", pubA),
		entry(srcID, "vps-01-api-g2", pubB),
	)

	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}

	kr, ok := reg.Keyring(srcID)
	if !ok {
		t.Fatal("keyring not found for source")
	}
	if len(kr) != 2 {
		t.Fatalf("keyring has %d keys, want 2 (both must be present)", len(kr))
	}
	if !kr["vps-01-api"].Equal(pubA) || !kr["vps-01-api-g2"].Equal(pubB) {
		t.Fatal("keyring does not hold both registered public keys by name")
	}

	// Source returns the most recently registered entry.
	sk, ok := reg.Source(srcID)
	if !ok || sk.KeyName != "vps-01-api-g2" {
		t.Fatalf("Source returned %q, want most-recent vps-01-api-g2", sk.KeyName)
	}

	if got := reg.SourceIDs(); len(got) != 1 || got[0] != srcID {
		t.Fatalf("SourceIDs = %v, want [%s] (deduplicated)", got, srcID)
	}
	if got := reg.SourceKeys(srcID); len(got) != 2 {
		t.Fatalf("SourceKeys returned %d, want 2", len(got))
	}
}

// TestRegistrySingleKeyUnchanged confirms a single-entry registry still loads
// and behaves identically to the previous single-key semantics.
func TestRegistrySingleKeyUnchanged(t *testing.T) {
	pub := genPub(t)
	path := filepath.Join(t.TempDir(), "keys.json")
	writeRegistry(t, path, entry(srcID, keyName, pub))

	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := reg.Source(srcID)
	if !ok || sk.KeyName != keyName {
		t.Fatalf("Source = %q ok=%v, want %q true", sk.KeyName, ok, keyName)
	}
	kr, ok := reg.Keyring(srcID)
	if !ok || len(kr) != 1 {
		t.Fatalf("Keyring size = %d ok=%v, want 1 true", len(kr), ok)
	}
}

// TestAppendKey appends a new key to an existing (and to a fresh) registry file
// and reloads it, proving single-host rotation registration works on disk.
func TestAppendKey(t *testing.T) {
	pubA, pubB := genPub(t), genPub(t)

	t.Run("appends to existing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keys.json")
		writeRegistry(t, path, entry(srcID, "vps-01-api", pubA))
		if err := AppendKey(path, SourceKey{SourceID: srcID, Origin: origin, KeyName: "vps-01-api-g2", PublicKey: pubB}); err != nil {
			t.Fatal(err)
		}
		reg, err := LoadRegistry(path)
		if err != nil {
			t.Fatal(err)
		}
		if kr, _ := reg.Keyring(srcID); len(kr) != 2 {
			t.Fatalf("after append, keyring has %d keys, want 2", len(kr))
		}
	})

	t.Run("creates when absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "new-keys.json")
		if err := AppendKey(path, SourceKey{SourceID: srcID, Origin: origin, KeyName: "vps-01-api", PublicKey: pubA}); err != nil {
			t.Fatal(err)
		}
		reg, err := LoadRegistry(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := reg.Source(srcID); !ok {
			t.Fatal("append to absent file did not create a loadable registry")
		}
	})
}
