// Package merkle implements the RFC 6962 §2.1 Merkle tree (SHA-256 with
// 0x00/0x01 domain separation) plus RFC 9162 §2.1.3/§2.1.4 inclusion and
// consistency proofs and their verification (REQ-C-01, REQ-C-02).
package merkle

import "crypto/sha256"

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// LeafHash returns SHA-256(0x00 || entry), the RFC 6962 leaf hash (REQ-C-01).
func LeafHash(entry []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(entry)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// nodeHash returns SHA-256(0x01 || left || right), the RFC 6962 node hash.
// Both operands are fixed 32-byte digests, so the preimage is assembled in a
// stack buffer and hashed in one shot — byte-identical to the streaming form
// but without the per-call heap allocation that dominated Root's alloc count on
// large trees (REQ-C-01).
func nodeHash(left, right [32]byte) [32]byte {
	var buf [65]byte
	buf[0] = nodePrefix
	copy(buf[1:33], left[:])
	copy(buf[33:65], right[:])
	return sha256.Sum256(buf[:])
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less
// than n (n > 1), the RFC 6962 split point.
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// Root computes the RFC 6962 Merkle Tree Hash over leaf hashes. The empty tree
// hashes to SHA-256("") (REQ-C-01).
func Root(leaves [][32]byte) [32]byte {
	n := len(leaves)
	if n == 0 {
		return sha256.Sum256(nil)
	}
	if n == 1 {
		return leaves[0]
	}
	k := largestPowerOfTwoLessThan(n)
	return nodeHash(Root(leaves[:k]), Root(leaves[k:]))
}

// RootFromEntries computes the root over raw entries, hashing each leaf first.
func RootFromEntries(entries [][]byte) [32]byte {
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = LeafHash(e)
	}
	return Root(leaves)
}

// InclusionProof returns the RFC 9162 §2.1.3.1 audit path for leaf m in a tree
// of the given leaf hashes (REQ-C-02).
func InclusionProof(leaves [][32]byte, m int) [][32]byte {
	return path(m, leaves)
}

func path(m int, leaves [][32]byte) [][32]byte {
	n := len(leaves)
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		return append(path(m, leaves[:k]), Root(leaves[k:]))
	}
	return append(path(m-k, leaves[k:]), Root(leaves[:k]))
}

// ConsistencyProof returns the RFC 9162 §2.1.4.1 proof that a tree of size m is
// a prefix of a tree of size n (0 < m <= n) (REQ-C-02).
func ConsistencyProof(leaves [][32]byte, m, n int) [][32]byte {
	if m <= 0 || m > n || n > len(leaves) {
		return nil
	}
	if m == n {
		return nil
	}
	return subproof(m, leaves[:n], true)
}

func subproof(m int, leaves [][32]byte, b bool) [][32]byte {
	n := len(leaves)
	if m == n {
		if b {
			return nil
		}
		return [][32]byte{Root(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(subproof(m, leaves[:k], b), Root(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), Root(leaves[:k]))
}

// VerifyInclusion checks an RFC 9162 §2.1.3.2 inclusion proof for leafHash at
// index m in a tree of size n against root (REQ-C-02).
func VerifyInclusion(leafHash [32]byte, m, n int, proof [][32]byte, root [32]byte) bool {
	if m >= n {
		return false
	}
	fn, sn := m, n-1
	r := leafHash
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

// VerifyConsistency checks an RFC 9162 §2.1.4.2 consistency proof between tree
// sizes m and n (0 < m < n) with roots oldRoot and newRoot (REQ-C-02).
func VerifyConsistency(m, n int, proof [][32]byte, oldRoot, newRoot [32]byte) bool {
	if m <= 0 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && oldRoot == newRoot
	}
	path := proof
	if isPowerOfTwo(m) {
		path = append([][32]byte{oldRoot}, path...)
	}
	if len(path) == 0 {
		return false
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return fr == oldRoot && sr == newRoot && sn == 0
}

func isPowerOfTwo(n int) bool {
	return n > 0 && n&(n-1) == 0
}
