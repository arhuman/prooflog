// Package segment batches records into upload/storage units, maintains the
// per-source RFC 6962 tree, and emits a signed C2SP tlog-checkpoint at each
// seal (REQ-C-01, REQ-C-07, REQ-C-14).
package segment

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/arhuman/prooflog/internal/merkle"
	"github.com/arhuman/prooflog/internal/note"
)

// Default seal thresholds (§4.3).
const (
	DefaultMaxRecords = 256
	DefaultMaxAge     = 60 * time.Second
)

// ID is a segment identifier: a UUIDv7 per RFC 9562 §5.7 (REQ-C-14).
type ID [16]byte

// NewID mints a time-ordered UUIDv7 from now using r for randomness (REQ-C-14).
func NewID(now time.Time, r io.Reader) (ID, error) {
	var id ID
	if _, err := io.ReadFull(r, id[6:]); err != nil {
		return ID{}, fmt.Errorf("segment: uuid random: %w", err)
	}
	ms := uint64(now.UnixMilli())
	id[0] = byte(ms >> 40)
	id[1] = byte(ms >> 32)
	id[2] = byte(ms >> 24)
	id[3] = byte(ms >> 16)
	id[4] = byte(ms >> 8)
	id[5] = byte(ms)
	id[6] = (id[6] & 0x0f) | 0x70 // version 7
	id[8] = (id[8] & 0x3f) | 0x80 // variant 10
	return id, nil
}

// String renders the canonical 8-4-4-4-12 UUID form.
func (id ID) String() string {
	h := hex.EncodeToString(id[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ParseID is the inverse of String: it parses the canonical 8-4-4-4-12 UUIDv7
// form and rejects anything else. It requires exactly 36 chars with dashes at
// positions 8/13/18/23, hex digits elsewhere, and the RFC 9562 §5.7 version
// (0x70) and variant (0x80) bits — so a hostile wire value cannot escape a
// blob path (REQ-C-14).
func ParseID(s string) (ID, error) {
	var id ID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return ID{}, fmt.Errorf("segment: invalid uuid format %q", s)
	}
	hexDigits := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err := hex.Decode(id[:], []byte(hexDigits)); err != nil {
		return ID{}, fmt.Errorf("segment: invalid uuid hex: %w", err)
	}
	if id[6]&0xf0 != 0x70 {
		return ID{}, fmt.Errorf("segment: not a uuidv7 (version bits)")
	}
	if id[8]&0xc0 != 0x80 {
		return ID{}, fmt.Errorf("segment: not a uuidv7 (variant bits)")
	}
	return id, nil
}

// Sealed is a sealed segment: its ID, seq range, tree root at seal time, and
// the signed checkpoint covering the whole source tree (REQ-C-07).
type Sealed struct {
	ID         ID
	Origin     string
	SeqFirst   uint64
	SeqLast    uint64
	TreeSize   uint64
	Root       [32]byte
	Checkpoint string
}

// Batcher accumulates leaf hashes for one source and seals segments when the
// record or age threshold is reached (REQ-C-14).
type Batcher struct {
	origin     string
	name       string
	priv       ed25519.PrivateKey
	maxRecords int
	maxAge     time.Duration
	rand       io.Reader

	tree        merkle.Hasher
	sealedUpto  int
	firstUnseal time.Time
	pending     int
}

// Option configures a Batcher.
type Option func(*Batcher)

// WithMaxRecords overrides the record-count seal threshold.
func WithMaxRecords(n int) Option { return func(b *Batcher) { b.maxRecords = n } }

// WithMaxAge overrides the age-based seal threshold.
func WithMaxAge(d time.Duration) Option { return func(b *Batcher) { b.maxAge = d } }

// WithRand overrides the randomness source for segment IDs (tests).
func WithRand(r io.Reader) Option { return func(b *Batcher) { b.rand = r } }

// New creates a Batcher for origin (e.g. prooflog/<org>/<source_id>) signing
// checkpoints with the Ed25519 key named name (REQ-C-07).
func New(origin, name string, priv ed25519.PrivateKey, opts ...Option) *Batcher {
	b := &Batcher{
		origin:     origin,
		name:       name,
		priv:       priv,
		maxRecords: DefaultMaxRecords,
		maxAge:     DefaultMaxAge,
		rand:       rand.Reader,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// SetSigner swaps the checkpoint signing identity to (name, priv) without
// touching the Merkle tree, sealed offset, or pending count. It underpins agent
// key rotation: subsequent Seal calls sign under the new key while the tree
// continues unbroken, so old checkpoints stay valid under the old key and new
// ones verify under the new key (REQ-C-07, REQ-C-11). The new name MUST differ
// from every prior name — the C2SP key id hashes name and public key together.
func (b *Batcher) SetSigner(name string, priv ed25519.PrivateKey) {
	b.name = name
	b.priv = priv
}

// Add appends a record's canonical bytes as the next leaf. seq must be
// contiguous (previous leaf count + 1). now is used to start the age timer.
func (b *Batcher) Add(recordBytes []byte, seq uint64, now time.Time) error {
	if seq != b.tree.Size()+1 {
		return fmt.Errorf("segment: non-contiguous seq %d, want %d", seq, b.tree.Size()+1)
	}
	b.tree.Add(merkle.LeafHash(recordBytes))
	if b.pending == 0 {
		b.firstUnseal = now
	}
	b.pending++
	return nil
}

// Restore re-adds an already-sealed record's canonical bytes as the next leaf
// and marks the tree sealed up to it. It reconstructs a batcher's Merkle state
// after an agent restart without emitting a checkpoint or re-uploading, so a
// later Seal covers only records appended since (REQ-C-01).
func (b *Batcher) Restore(recordBytes []byte) {
	b.tree.Add(merkle.LeafHash(recordBytes))
	b.sealedUpto = int(b.tree.Size())
}

// Ready reports whether the pending records meet a seal threshold at now.
func (b *Batcher) Ready(now time.Time) bool {
	if b.pending == 0 {
		return false
	}
	if b.pending >= b.maxRecords {
		return true
	}
	return now.Sub(b.firstUnseal) >= b.maxAge
}

// Pending returns the number of unsealed records.
func (b *Batcher) Pending() int { return b.pending }

// Seal seals the pending records into a segment, computes the source tree root
// at the new size, and signs a tlog-checkpoint (REQ-C-01, REQ-C-07).
func (b *Batcher) Seal(now time.Time) (Sealed, error) {
	if b.pending == 0 {
		return Sealed{}, fmt.Errorf("segment: nothing to seal")
	}
	id, err := NewID(now, b.rand)
	if err != nil {
		return Sealed{}, err
	}
	size := int(b.tree.Size())
	root := b.tree.Root()
	cp := note.Checkpoint{Origin: b.origin, Size: uint64(size), Hash: root}
	signed, err := note.Sign(cp.Marshal(), b.name, b.priv)
	if err != nil {
		return Sealed{}, fmt.Errorf("segment: sign checkpoint: %w", err)
	}
	sealed := Sealed{
		ID:         id,
		Origin:     b.origin,
		SeqFirst:   uint64(b.sealedUpto + 1),
		SeqLast:    uint64(size),
		TreeSize:   uint64(size),
		Root:       root,
		Checkpoint: signed,
	}
	b.sealedUpto = size
	b.pending = 0
	return sealed, nil
}
