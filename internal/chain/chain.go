// Package chain links and verifies per-source hash chains: each record's
// prev_hash points at the previous record's hash, sequences are strictly
// monotonic with no gaps, and hashes cover the exact stored bytes (REQ-C-03,
// REQ-C-04).
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/arhuman/prooflog/internal/envelope"
)

// Genesis is the prev_hash of the first record in a chain: 64 zero hex chars.
const Genesis = envelope.ZeroHash

// Entry is one stored record: its exact bytes and its claimed hash.
type Entry struct {
	Bytes []byte
	Hash  string
}

// HashError reports a record whose claimed hash does not cover its bytes.
type HashError struct {
	Seq          uint64
	ClaimedHash  string
	ComputedHash string
}

func (e *HashError) Error() string {
	return fmt.Sprintf("chain: seq %d hash mismatch: claimed %s computed %s", e.Seq, e.ClaimedHash, e.ComputedHash)
}

// GapError reports a break in strict sequence monotonicity.
type GapError struct {
	ExpectedSeq uint64
	GotSeq      uint64
}

func (e *GapError) Error() string {
	return fmt.Sprintf("chain: sequence gap: expected seq %d, got %d", e.ExpectedSeq, e.GotSeq)
}

// LinkError reports a prev_hash that does not link to the previous record.
type LinkError struct {
	Seq          uint64
	ExpectedPrev string
	GotPrev      string
}

func (e *LinkError) Error() string {
	return fmt.Sprintf("chain: seq %d prev_hash mismatch: expected %s, got %s", e.Seq, e.ExpectedPrev, e.GotPrev)
}

// Verify checks a contiguous sequence of stored records: each claimed hash
// covers its bytes, prev_hash links to the previous record (Genesis for the
// first), and seq is strictly monotonic with no gaps. It returns a structured
// *HashError, *GapError, or *LinkError usable by the verifier (REQ-C-04).
func Verify(entries []Entry) error {
	prevHash := Genesis
	var prevSeq uint64
	for i, e := range entries {
		sum := sha256.Sum256(e.Bytes)
		computed := hex.EncodeToString(sum[:])
		if computed != e.Hash {
			return &HashError{Seq: prevSeq + 1, ClaimedHash: e.Hash, ComputedHash: computed}
		}
		rec, err := envelope.Parse(e.Bytes)
		if err != nil {
			return fmt.Errorf("chain: entry %d: %w", i, err)
		}
		if i > 0 && rec.Seq != prevSeq+1 {
			return &GapError{ExpectedSeq: prevSeq + 1, GotSeq: rec.Seq}
		}
		if rec.PrevHash != prevHash {
			return &LinkError{Seq: rec.Seq, ExpectedPrev: prevHash, GotPrev: rec.PrevHash}
		}
		prevHash = computed
		prevSeq = rec.Seq
	}
	return nil
}
