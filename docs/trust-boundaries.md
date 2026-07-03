# Trust boundaries — who verifies what, and why

This document makes the prooflog trust model explicit: at each hop an evidence
record takes, which party checks which property, and what each party
deliberately does *not* check. It is the companion to ADR-0009 (store trust
model) and ADR-0005 (external anchoring / separation of powers).

The guiding principle: **each component verifies what it can cheaply and
authoritatively assert, and defers the rest to the party that holds the
necessary secret or context.** Necessary checks are pushed as early as possible
(fail fast, with attribution); sufficiency is established offline by the
verifier, which holds the trusted keys.

## The pipeline

```
  event source ──▶ agent ──▶ store ──▶ verifier (offline)
                    │          │           │
                 seals &    persists,   recomputes &
                 signs      binds       authenticates
```

## Who verifies what

| Property | Agent | Store (ingest) | Verifier (offline) |
|---|---|---|---|
| Record well-formedness (schema, required fields) | produces | re-parses each frame | re-parses |
| Per-frame hash = SHA-256(record bytes) | produces | **checks** | checks |
| Hash-chain linkage (`prev_hash`) | produces | — | **checks** |
| Frame seq contiguous within `[seq_first, seq_last]` | produces | **checks** | checks |
| Frame `source_id` = segment `source_id` | produces | **checks** | checks |
| `meta.Root` = checkpoint-committed root (binding) | produces | **checks** | — (implied by below) |
| `meta.SeqLast` = checkpoint-committed tree size | produces | **checks** | — |
| Cumulative RFC 6962 root = checkpoint root (`RootsValid`) | produces | defers (O(history)) | **checks** |
| Checkpoint **signature** under a trusted key | signs | defers (no keys) | **checks** |
| Append-only checkpoint consistency (no forks) | — | — | **checks** |
| Retention/hold exemption of gaps | — | records tombstones | **checks** |
| External timestamp (anchor) | — | — | **checks** (ADR-0005) |

Bold = the authoritative checker for that property. Non-bold cells that still act
(e.g. the store re-parsing frames) are defense-in-depth or prerequisites, not the
property's authority.

## Why the store stops where it does

The store is the least-trusted long-lived component: it is where a compromised or
buggy operator would tamper. So it verifies everything it can assert **from the
bytes in hand**, and nothing that would require secrets it does not hold or
history it would have to re-read:

- **It binds, it does not recompute.** `meta.Root` is a *cumulative* RFC 6962
  root over the source's whole history `[1..seq_last]`, but an upload carries only
  the segment's own frames `[seq_first..seq_last]`. Recomputing the cumulative
  root would force the store to re-read every prior blob of the source on every
  upload — O(history) per upload. Instead the store checks that `meta.Root` and
  `meta.SeqLast` match the `(root, size)` committed in the signed checkpoint the
  segment carries. This is O(1) and catches a lying or absent root (e.g. an
  all-zero root) at ingest. See ADR-0009.
- **It does not verify checkpoint signatures.** The store holds no pinned
  per-source public keys; distributing them to the store is out of scope. A
  signature check without trusted keys is meaningless, so authenticity is left to
  the verifier, which owns the key registry.

The store's ingest checks are therefore **necessary but not sufficient**: they
stop a segment that is internally inconsistent, but only the verifier — with the
trusted keys and the full pulled history — establishes that the evidence is
authentic and cumulatively intact.

## Why the verifier is the authority

The verifier is deployed outside the store operator's perimeter (ADR-0005) and
holds the per-source public-key registry. It pulls the exact stored frames,
recomputes the hash chain and cumulative Merkle roots, verifies checkpoint
signatures against trusted keys, enforces append-only consistency (fork
detection), and reconciles gaps against the tombstone/hold set. Because it sees
only roots, sequences, heartbeats, and signatures — never payloads — third-party
hosting stays compatible with client-side encryption.

## Residual limits (documented, not silent)

- **Fully self-hosted deployments.** When agent, store, and verifier are all
  under one administrator, an operator can rewrite history and re-sign it
  end-to-end; the ingest binding does not change this. External anchoring
  (ADR-0005, RFC 3161) is the mitigation, and the caveat is surfaced to
  operators.
- **The store trusts the checkpoint it is handed for the binding check.** The
  binding proves `meta.Root`/`meta.SeqLast` agree with *a* checkpoint, not that
  the checkpoint is authentic — that is the verifier's job. A compromised agent
  can still sign a self-consistent lie; the verifier catches it via signature and
  cross-checkpoint consistency, and the anchor catches wholesale rewrites.
