package merkle

import (
	"crypto/sha256"
	"math/bits"
)

// Hasher incrementally computes RFC 6962 Merkle Tree Hashes over every prefix
// of a leaf stream in a single left-to-right pass (REQ-C-01). It is the
// transparency-log "hash stack" / compact-range construction: the stack holds
// the roots of the perfect subtrees whose sizes are exactly the set bits in the
// binary representation of n, folded right-to-left to yield the current root.
//
// Root, InclusionProof and ConsistencyProof remain the recursive RFC 6962
// reference implementation; Hasher trades that O(n)-per-prefix recompute for
// O(1) amortised Add and O(log n) Root, and its equivalence to Root is machine
// checked differentially (see hasher_test.go), never assumed (REQ-C-02).
type Hasher struct {
	stack [][32]byte // roots of perfect subtrees, sizes = binary decomposition of n
	n     uint64
}

// Add appends one leaf hash. After the increment, k = TrailingZeros64(n) equals
// the number of low set bits that just carried, i.e. the number of equal-height
// perfect subtrees to merge — the standard binary-counter carry propagation.
func (h *Hasher) Add(leaf [32]byte) {
	h.n++
	h.stack = append(h.stack, leaf)
	for k := bits.TrailingZeros64(h.n); k > 0; k-- {
		right := h.stack[len(h.stack)-1]
		left := h.stack[len(h.stack)-2]
		h.stack = h.stack[:len(h.stack)-2]
		h.stack = append(h.stack, nodeHash(left, right))
	}
}

// Root returns the RFC 6962 Merkle Tree Hash over the leaves added so far. The
// empty tree hashes to SHA-256("") like Root. Otherwise the perfect-subtree
// roots on the stack are folded right-to-left, matching the RFC 6962 split rule
// nodeHash(perfectPrefix, MTH(rest)) by induction on the remaining bits.
func (h *Hasher) Root() [32]byte {
	if h.n == 0 {
		return sha256.Sum256(nil)
	}
	r := h.stack[len(h.stack)-1]
	for i := len(h.stack) - 2; i >= 0; i-- {
		r = nodeHash(h.stack[i], r)
	}
	return r
}

// Size returns the number of leaves added so far.
func (h *Hasher) Size() uint64 {
	return h.n
}
