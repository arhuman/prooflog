package seal

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	id := newIdentity(t)
	var s AgeSealer
	plaintext := []byte(`{"secret":"payload"}`)
	ct, err := s.Seal(plaintext, []Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := s.Open(ct, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestSealNoRecipients(t *testing.T) {
	t.Parallel()
	var s AgeSealer
	if _, err := s.Seal([]byte("x"), nil); err == nil {
		t.Fatal("expected error with no recipients")
	}
}

func TestOpenWrongIdentityFails(t *testing.T) {
	t.Parallel()
	var s AgeSealer
	ct, err := s.Seal([]byte("x"), []Recipient{newIdentity(t).Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ct, newIdentity(t)); err == nil {
		t.Fatal("open should fail with wrong identity")
	}
}

func TestMultiRecipient(t *testing.T) {
	t.Parallel()
	a, b := newIdentity(t), newIdentity(t)
	var s AgeSealer
	ct, err := s.Seal([]byte("shared"), []Recipient{a.Recipient(), b.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []*age.X25519Identity{a, b} {
		got, err := s.Open(ct, id)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "shared" {
			t.Fatal("multi-recipient open mismatch")
		}
	}
}

func TestBase64Helpers(t *testing.T) {
	t.Parallel()
	ct := []byte{0x00, 0x01, 0xff, 0x7f}
	enc := EncodeBase64(ct)
	dec, err := DecodeBase64(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, ct) {
		t.Fatal("base64 round trip mismatch")
	}
	if _, err := DecodeBase64("!!!not-base64!!!"); err == nil {
		t.Fatal("expected decode error")
	}
}

var _ Sealer = AgeSealer{}
