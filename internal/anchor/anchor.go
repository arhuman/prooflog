// Package anchor externally timestamps signed checkpoints (REQ-C-15).
//
// An Anchor is not a Verifier: the verifier actively checks consistency and
// relies on organizational independence; an anchor passively commits bytes
// to an external authority, proving existence-at-time even when the
// verifier is not independent. See docs/architecture.md, "Anchor vs Verifier
// — two trust roles".
package anchor

import (
	"context"
	"time"
)

// Anchor externally timestamps the exact bytes of a signed checkpoint note,
// binding them to an authority-attested time (REQ-C-15).
type Anchor interface {
	// Anchor timestamps the exact bytes of a signed checkpoint note.
	Anchor(ctx context.Context, signedNote []byte) (Receipt, error)
	// Name identifies the anchor (e.g. the TSA URL) for logs and reports.
	Name() string
}

// Receipt is the durable, offline-verifiable record of one external timestamp.
// The full DER TimeStampToken is stored whole so a receipt can be verified
// later without contacting the TSA (e.g. `openssl ts -verify`), per REQ-C-15.
type Receipt struct {
	Origin     string    `json:"origin"`
	Size       uint64    `json:"size"`
	RootB64    string    `json:"root"`
	TSA        string    `json:"tsa"`
	Token      []byte    `json:"token"` // full DER TimeStampToken (REQ-C-15)
	GenTime    time.Time `json:"gen_time"`
	AnchoredAt time.Time `json:"anchored_at"`
	Qualified  bool      `json:"qualified"` // operator-declared eIDAS-qualified TSA
}
