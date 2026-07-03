// Package note implements the C2SP signed-note format and tlog-checkpoint
// bodies. Signatures are Ed25519 over domain-separated, structured text — never
// bare hashes (REQ-C-05, REQ-C-06, REQ-C-07).
package note

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/arhuman/prooflog/internal/hashid"
)

// algEd25519 is the C2SP signed-note algorithm byte for Ed25519.
const algEd25519 = 0x01

// sigPrefix begins every signature line: em dash (U+2014) then a space.
const sigPrefix = "— "

// KeyID returns the 4-byte C2SP key ID: the first 4 bytes of
// SHA-256(name || 0x0A || 0x01 || publicKey) (REQ-C-06).
func KeyID(name string, pub ed25519.PublicKey) [4]byte {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x0A, algEd25519})
	h.Write(pub)
	var id [4]byte
	copy(id[:], h.Sum(nil)[:4])
	return id
}

var (
	// ErrMalformed signals a note that is not well formed.
	ErrMalformed = errors.New("note: malformed")
	// ErrNoSignature signals no signature line matched the given key.
	ErrNoSignature = errors.New("note: no matching signature")
	// ErrBadSignature signals a signature that failed verification.
	ErrBadSignature = errors.New("note: bad signature")
)

// Sign wraps text in a C2SP signed note carrying a single Ed25519 signature by
// key name. The text must end in a newline; the signature covers exactly that
// text (REQ-C-05, REQ-C-06).
func Sign(text, name string, priv ed25519.PrivateKey) (string, error) {
	if !strings.HasSuffix(text, "\n") {
		return "", fmt.Errorf("%w: text must end in newline", ErrMalformed)
	}
	pub := priv.Public().(ed25519.PublicKey)
	id := KeyID(name, pub)
	sig := ed25519.Sign(priv, []byte(text))
	blob := append(id[:], sig...)
	line := sigPrefix + name + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
	return text + "\n" + line, nil
}

// Verify parses a signed note, checks the signature for key name against pub,
// and returns the signed text (REQ-C-05).
func Verify(signed, name string, pub ed25519.PublicKey) (string, error) {
	split := strings.LastIndex(signed, "\n\n")
	if split < 0 {
		return "", fmt.Errorf("%w: no signature block", ErrMalformed)
	}
	text := signed[:split+1]
	sigs := signed[split+2:]
	if len(sigs) == 0 || !strings.HasSuffix(sigs, "\n") {
		return "", fmt.Errorf("%w: empty signature block", ErrMalformed)
	}
	want := KeyID(name, pub)
	for _, line := range strings.Split(strings.TrimRight(sigs, "\n"), "\n") {
		if !strings.HasPrefix(line, sigPrefix) {
			return "", fmt.Errorf("%w: bad signature line", ErrMalformed)
		}
		rest := line[len(sigPrefix):]
		sp := strings.IndexByte(rest, ' ')
		if sp < 0 {
			return "", fmt.Errorf("%w: bad signature line", ErrMalformed)
		}
		if rest[:sp] != name {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(rest[sp+1:])
		if err != nil || len(blob) != 4+ed25519.SignatureSize {
			return "", fmt.Errorf("%w: bad signature encoding", ErrMalformed)
		}
		if [4]byte(blob[:4]) != want {
			continue
		}
		if !ed25519.Verify(pub, []byte(text), blob[4:]) {
			return "", ErrBadSignature
		}
		return text, nil
	}
	return "", ErrNoSignature
}

// Checkpoint is a C2SP tlog-checkpoint body: origin, tree size, RFC 6962 root,
// and optional extension lines (REQ-C-07).
type Checkpoint struct {
	Origin     string
	Size       uint64
	Hash       [32]byte
	Extensions []string
}

// Marshal renders the checkpoint text: line 1 origin, line 2 ASCII decimal tree
// size, line 3 base64 root, then any extension lines, each newline-terminated
// (REQ-C-07).
func (c Checkpoint) Marshal() string {
	var b strings.Builder
	b.WriteString(c.Origin)
	b.WriteByte('\n')
	b.WriteString(strconv.FormatUint(c.Size, 10))
	b.WriteByte('\n')
	b.WriteString(base64.StdEncoding.EncodeToString(c.Hash[:]))
	b.WriteByte('\n')
	for _, ext := range c.Extensions {
		b.WriteString(ext)
		b.WriteByte('\n')
	}
	return b.String()
}

// CheckpointOf extracts and parses the tlog-checkpoint body from a signed note
// WITHOUT verifying its signature. It splits off the trailing signature block
// (the text after the final blank line) and parses what precedes it. Callers
// that need authenticity must also Verify against a trusted key; this is for
// paths that only need the committed (size, root) — e.g. the store binding a
// segment's declared root to the checkpoint it persists, or rebuilding a head
// index from trusted local storage (REQ-C-07).
func CheckpointOf(signed string) (Checkpoint, error) {
	split := strings.LastIndex(signed, "\n\n")
	if split < 0 {
		return Checkpoint{}, fmt.Errorf("%w: no signature block", ErrMalformed)
	}
	return ParseCheckpoint(signed[:split+1])
}

// ParseCheckpoint parses a tlog-checkpoint body (REQ-C-07).
func ParseCheckpoint(text string) (Checkpoint, error) {
	if !strings.HasSuffix(text, "\n") {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint must end in newline", ErrMalformed)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return Checkpoint{}, fmt.Errorf("%w: checkpoint needs 3 lines", ErrMalformed)
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: tree size: %v", ErrMalformed, err)
	}
	rootBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: root hash", ErrMalformed)
	}
	root, err := hashid.ParseDigest(rootBytes)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: root hash", ErrMalformed)
	}
	cp := Checkpoint{Origin: lines[0], Size: size}
	cp.Hash = root
	if len(lines) > 3 {
		cp.Extensions = lines[3:]
	}
	return cp, nil
}
