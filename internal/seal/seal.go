// Package seal encrypts and decrypts record payloads with the age format
// (ChaCha20-Poly1305, per-file single-use keys, X25519 recipients). The Sealer
// interface is kept AEAD-agnostic so a FIPS mode can substitute AES-256-GCM
// (REQ-C-08, REQ-C-10).
package seal

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
)

// maxPlaintext bounds decrypted output to guard against decompression-style
// resource exhaustion.
const maxPlaintext = 64 << 20

// Recipient is an encryption target (age X25519 recipient in v1).
type Recipient = age.Recipient

// Identity is a decryption key (age X25519 identity in v1).
type Identity = age.Identity

// Sealer encrypts payloads to recipients and opens them with an identity.
type Sealer interface {
	Seal(plaintext []byte, recipients []Recipient) ([]byte, error)
	Open(ciphertext []byte, identity Identity) ([]byte, error)
}

// AgeSealer is the v1 Sealer backed by filippo.io/age (REQ-C-08).
type AgeSealer struct{}

// Seal encrypts plaintext to the given recipients (REQ-C-08).
func (AgeSealer) Seal(plaintext []byte, recipients []Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("seal: no recipients")
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("seal: encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("seal: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("seal: close: %w", err)
	}
	return buf.Bytes(), nil
}

// Open decrypts ciphertext with the given identity (REQ-C-08).
func (AgeSealer) Open(ciphertext []byte, identity Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("seal: decrypt: %w", err)
	}
	limited := &io.LimitedReader{R: r, N: maxPlaintext + 1}
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("seal: read: %w", err)
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("seal: plaintext exceeds %d bytes", maxPlaintext)
	}
	return out, nil
}

// EncodeBase64 encodes ciphertext for embedding in a record's payload_ct field.
func EncodeBase64(ciphertext []byte) string {
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// DecodeBase64 decodes a record's payload_ct field back to ciphertext.
func DecodeBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("seal: decode base64: %w", err)
	}
	return b, nil
}
