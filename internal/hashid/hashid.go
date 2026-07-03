// Package hashid defines Digest, the domain's core 32-byte value: record
// hashes, Merkle roots, and checkpoint roots (REQ-C-01, REQ-C-07). Its fixed
// size makes a wrong-length digest unrepresentable, so parsing untrusted []byte
// or hex once at a trust boundary (ParseDigest / ParseHexDigest) replaces the
// scattered len==32 runtime checks. Digest's underlying type is [32]byte, so it
// interoperates directly with the crypto core (merkle, note) without explicit
// conversions.
package hashid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Size is the length of a Digest in bytes (SHA-256).
const Size = sha256.Size

// Digest is a SHA-256 digest.
type Digest [Size]byte

// Hex returns the lowercase hex encoding of the digest.
func (d Digest) Hex() string { return hex.EncodeToString(d[:]) }

// String implements fmt.Stringer as the hex encoding.
func (d Digest) String() string { return d.Hex() }

// Bytes returns a fresh []byte copy of the digest, for byte-slice boundaries
// such as proto fields and SQL BLOB columns. The copy keeps callers from
// aliasing (and mutating) the digest's backing array.
func (d Digest) Bytes() []byte {
	b := make([]byte, Size)
	copy(b, d[:])
	return b
}

// ParseDigest converts a byte slice to a Digest, rejecting any length != Size.
// It is the single boundary for turning an untrusted []byte (a proto root, a
// BLOB column) into a fixed-size digest.
func ParseDigest(b []byte) (Digest, error) {
	if len(b) != Size {
		return Digest{}, fmt.Errorf("hashid: digest must be %d bytes, got %d", Size, len(b))
	}
	return Digest(b), nil
}

// ParseHexDigest converts a hex string to a Digest, rejecting a wrong length or
// non-hex input.
func ParseHexDigest(s string) (Digest, error) {
	if len(s) != 2*Size {
		return Digest{}, fmt.Errorf("hashid: hex digest must be %d chars, got %d", 2*Size, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return Digest{}, fmt.Errorf("hashid: parse hex digest: %w", err)
	}
	return Digest(b), nil
}
