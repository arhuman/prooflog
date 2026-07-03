# 5. External anchoring strategy

Date: 2026-07-04

## Status

Accepted

## Context

An evidence chain whose operator also controls the anchor provides no separation
of powers: a malicious operator could rewrite the chain and re-anchor it. Three
options were considered:

- **RFC 3161 TSA:** standards-based external timestamping, legal presumption
  under eIDAS Art. 41 for qualified TSAs, but introduces an external dependency
  and per-stamp cost.
- **Rekor (sigstore):** public append-only log; strong non-repudiation, but
  requires internet access from the verifier and a dependency on sigstore
  infrastructure.
- **Independently hosted verifier:** no external service dependency, low cost,
  preserves privacy (verifier sees only roots/sequences/heartbeats/signatures,
  never payloads), achieves separation of powers when hosted at a third party.

A pluggable `Anchor` interface was designed from the start so that RFC 3161
and Rekor could be added later without rewriting the verifier core.

## Decision

In v1, the verifier acts as the anchor, hosted outside the store operator's
perimeter. The verifier receives only roots, sequences, heartbeats, and
signatures — never payloads — making third-party hosting compatible with
client-side encryption.

A pluggable `Anchor` interface (REQ-C-15) is implemented in the `internal/anchor`
package. The v1 implementation is an RFC 3161 TSA client; eIDAS-qualified TSA
and Rekor adapters remain planned.

**Residual limit (documented, not silent):** in fully self-hosted deployments
where agent, store, and verifier are all under the same admin, rewriting remains
undetectable. Operators must be informed of this caveat.

**Accepted risk:** without an eIDAS-qualified TSA, evidence carries no legal
timestamp presumption. The hosted verifier only provides separation of powers
if operators actually deploy it at an independent party.

## Consequences

**Positive.** Third-party verifier hosting is low-cost and preserves payload
privacy. The `Anchor` interface keeps future upgrades (eIDAS-qualified TSA,
Rekor) non-breaking. The RFC 3161 TSA client moves evidence toward the eIDAS
Art. 41 timestamp presumption.

**Negative.** Self-hosted deployments lack separation of powers (documented
caveat). Without a qualified TSA, the trust model relies on organizational
separation, not cryptographic third-party proof.

## References

- ADR-0001 item 5 — qualified-timestamp anchoring
- `docs/standards.md` REQ-C-15 — anchoring interface requirement
- `internal/anchor` — `Anchor` interface and RFC 3161 TSA implementation
