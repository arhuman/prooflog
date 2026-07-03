# 4. Cryptographic construction

Date: 2026-07-03

## Status

Accepted

## Context

Evidence integrity depends on the cryptographic construction being standard,
independently citable, and auditable by a court-facing forensic examiner. Novel
constructions (custom nonce extensions, non-standardized drafts) create
defensibility risk when evidence is challenged.

Two early candidate choices were reconsidered:
- XChaCha20: no completed IRTF standard, standardized nowhere; single-use file
  keys remove the extended-nonce motivation, so XChaCha20 provides no benefit.
- Re-canonicalization of JSON before hashing (e.g., RFC 8785 JCS): adds
  complexity and creates a canonicalization mismatch risk; hashing bytes exactly
  as stored is simpler and eliminates the risk.

See `docs/standards.md` for the full requirements register (REQ-C/E/R).

## Decision

Adopt a "boring composite" where every building block is a published standard
or an actively maintained specification:

**Hash chain and Merkle tree**
- Hash chain per source; events grouped into segments (upload units).
- Append-only Merkle tree per source, RFC 6962 §2.1 construction (0x00/0x01
  domain-separation prefixes).
- Checkpoints in C2SP tlog-checkpoint format, signed as C2SP signed notes
  (Ed25519, RFC 8032 / FIPS 186-5). Bit-level compatible with the tlog
  ecosystem (sumdb, sigsum, Rekor).

**Payload encryption**
- age format (`filippo.io/age`, C2SP spec): ChaCha20-Poly1305 (RFC 8439),
  single-use file key, org X25519 recipient.
- XChaCha20 rejected: dead IRTF draft, no completed standard; single-use keys
  remove the extended-nonce argument.
- Payloads decrypt with the standard `age` CLI — no prooflog-specific tooling
  required for decryption.

**Serialization invariants**
- Hash the stored bytes exactly as stored; never re-canonicalize JSON (RFC 8785
  cited as the rationale for this non-adoption).
- RFC 3339 UTC timestamp format pinned to the byte.
- Segment IDs as UUIDv7 (RFC 9562).

**Key custody (age-style)**
- `prooflog init` generates an Ed25519 signing keypair per agent (private key
  stays on the host) and an X25519 recipient keypair per organization (private
  key printed/backed up at init, never uploaded).
- Server and verifier see only public keys.
- Key rotation via `key_id` in the envelope. Agent key compromise triggers a
  revocation event and re-key, with a documented window between compromise and
  revocation.

**Accepted risk:** shipping client-side crypto in the first public version
invites early scrutiny from day one. This is intentional. The "boring
composite" choice and the documented threat model are the mitigation; real-world
feedback before the public launch hardens both.

## Consequences

**Positive.** Every component is independently auditable against published RFCs
and C2SP specs. age payloads are independently decryptable without prooflog
tooling. Merkle construction is compatible with existing tlog tooling (sumdb,
sigsum, Rekor).

**Negative / constraints.** Vocabulary is constrained: use "client-side
encrypted", never "zero-knowledge" (§ risk 3 in docs). Single-use file keys
mean no deduplication at the ciphertext level. On-disk format was changed
before any format freeze to add pseudonymous actor IDs and encrypted label
support (see ADR-0001 item 4).

## References

- `docs/standards.md` — requirements register (REQ-C/E/R)
- RFC 6962 — Certificate Transparency Merkle tree
- RFC 8032 / FIPS 186-5 — Ed25519
- RFC 8439 — ChaCha20-Poly1305
- RFC 8785 — JSON Canonicalization Scheme (cited as rationale for non-adoption)
- RFC 9562 — UUIDv7
- C2SP tlog-checkpoint and signed-note specifications
- ADR-0001 item 4 — metadata privacy model (format-breaking change)
