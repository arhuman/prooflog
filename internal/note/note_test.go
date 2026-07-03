package note

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestKeyIDDeterministic(t *testing.T) {
	t.Parallel()
	pub, _ := testKey(t)
	a := KeyID("vps-01-api", pub)
	b := KeyID("vps-01-api", pub)
	if a != b {
		t.Fatal("KeyID not deterministic")
	}
	if KeyID("other", pub) == a {
		t.Fatal("KeyID should depend on name")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv := testKey(t)
	text := "prooflog/acme/vps-01/api\n1842\ncm9vdA==\n"
	signed, err := Sign(text, "vps-01-api", priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signed, "\n\n"+sigPrefix) {
		t.Fatalf("missing blank-line-separated signature block:\n%s", signed)
	}
	got, err := Verify(signed, "vps-01-api", pub)
	if err != nil {
		t.Fatal(err)
	}
	if got != text {
		t.Fatalf("verified text = %q, want %q", got, text)
	}
}

func TestSignRequiresTrailingNewline(t *testing.T) {
	t.Parallel()
	_, priv := testKey(t)
	if _, err := Sign("no newline", "k", priv); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	t.Parallel()
	pub, priv := testKey(t)
	signed, err := Sign("body line\n", "k", priv)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(signed, "body", "evil", 1)
	if _, err := Verify(tampered, "k", pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	t.Parallel()
	_, priv := testKey(t)
	other, _ := testKey(t)
	signed, _ := Sign("body\n", "k", priv)
	if _, err := Verify(signed, "k", other); err == nil {
		t.Fatal("verify should fail with wrong key")
	}
}

func TestVerifyUnknownName(t *testing.T) {
	t.Parallel()
	pub, priv := testKey(t)
	signed, _ := Sign("body\n", "k", priv)
	if _, err := Verify(signed, "nobody", pub); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("want ErrNoSignature, got %v", err)
	}
}

func TestCheckpointMarshalParse(t *testing.T) {
	t.Parallel()
	var root [32]byte
	for i := range root {
		root[i] = byte(i)
	}
	tests := []struct {
		name string
		cp   Checkpoint
	}{
		{"no ext", Checkpoint{Origin: "prooflog/acme/vps-01/api", Size: 1842, Hash: root}},
		{"with ext", Checkpoint{Origin: "prooflog/acme/db", Size: 7, Hash: root, Extensions: []string{"foo bar", "baz"}}},
		{"zero size", Checkpoint{Origin: "o", Size: 0, Hash: root}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := tt.cp.Marshal()
			if !strings.HasSuffix(text, "\n") {
				t.Fatal("checkpoint must end in newline")
			}
			got, err := ParseCheckpoint(text)
			if err != nil {
				t.Fatal(err)
			}
			if got.Origin != tt.cp.Origin || got.Size != tt.cp.Size || got.Hash != tt.cp.Hash {
				t.Fatalf("roundtrip mismatch: %+v vs %+v", got, tt.cp)
			}
			if len(tt.cp.Extensions) != len(got.Extensions) {
				t.Fatalf("extensions mismatch: %v vs %v", got.Extensions, tt.cp.Extensions)
			}
		})
	}
}

func TestCheckpointInSignedNote(t *testing.T) {
	t.Parallel()
	pub, priv := testKey(t)
	var root [32]byte
	root[0] = 0xAB
	cp := Checkpoint{Origin: "prooflog/acme/vps-01/api", Size: 1842, Hash: root}
	signed, err := Sign(cp.Marshal(), "vps-01-api", priv)
	if err != nil {
		t.Fatal(err)
	}
	text, err := Verify(signed, "vps-01-api", pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCheckpoint(text)
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != 1842 || got.Hash != root {
		t.Fatal("checkpoint content not preserved through signed note")
	}
}
