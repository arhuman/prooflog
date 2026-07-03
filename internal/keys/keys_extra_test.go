package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadAgentKeyErrors covers the error branches of LoadAgentKey.
func TestLoadAgentKeyErrors(t *testing.T) {
	t.Parallel()
	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadAgentKey("/no/such/path/agent.key"); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent.key")
		if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAgentKey(path); err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("bad base64 public key", func(t *testing.T) {
		f := agentKeyFile{
			Name:    "test",
			Created: time.Now(),
			Alg:     "ed25519",
			Public:  "!!not-base64!!",
			Private: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)),
		}
		b, _ := json.Marshal(f)
		path := filepath.Join(t.TempDir(), "agent.key")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAgentKey(path); err == nil {
			t.Fatal("expected error for bad base64 public key")
		}
	})

	t.Run("bad base64 private key", func(t *testing.T) {
		f := agentKeyFile{
			Name:    "test",
			Created: time.Now(),
			Alg:     "ed25519",
			Public:  base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
			Private: "!!not-base64!!",
		}
		b, _ := json.Marshal(f)
		path := filepath.Join(t.TempDir(), "agent.key")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAgentKey(path); err == nil {
			t.Fatal("expected error for bad base64 private key")
		}
	})

	t.Run("wrong key sizes", func(t *testing.T) {
		f := agentKeyFile{
			Name:    "test",
			Created: time.Now(),
			Alg:     "ed25519",
			Public:  base64.StdEncoding.EncodeToString([]byte("tooshort")),
			Private: base64.StdEncoding.EncodeToString([]byte("tooshort")),
		}
		b, _ := json.Marshal(f)
		path := filepath.Join(t.TempDir(), "agent.key")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAgentKey(path); err == nil {
			t.Fatal("expected error for wrong key sizes")
		}
	})
}

// TestSaveAgentKeyWriteError covers the os.WriteFile error branch in SaveAgentKey.
func TestSaveAgentKeyWriteError(t *testing.T) {
	t.Parallel()
	k, err := GenerateAgentKey("test-key", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveAgentKey("/no/such/directory/agent.key", k); err == nil {
		t.Fatal("expected write error for non-existent directory")
	}
}

// TestLoadOrgKeyErrors covers the error branches of LoadOrgKey.
func TestLoadOrgKeyErrors(t *testing.T) {
	t.Parallel()
	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadOrgKey("/no/such/path/org.key"); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "org.key")
		if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrgKey(path); err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("invalid age identity string", func(t *testing.T) {
		f := orgKeyFile{
			Name:     "test",
			Created:  time.Now(),
			Alg:      "age-x25519",
			Identity: "AGE-SECRET-KEY-NOT-VALID",
		}
		b, _ := json.Marshal(f)
		path := filepath.Join(t.TempDir(), "org.key")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrgKey(path); err == nil {
			t.Fatal("expected error for invalid age identity string")
		}
	})
}

// TestSaveOrgKeyWriteError covers the os.WriteFile error branch in SaveOrgKey.
func TestSaveOrgKeyWriteError(t *testing.T) {
	t.Parallel()
	k, err := GenerateOrgKey("test-org", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveOrgKey("/no/such/directory/org.key", k); err == nil {
		t.Fatal("expected write error for non-existent directory")
	}
}
