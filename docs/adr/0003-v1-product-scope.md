# 3. v1 product scope

Date: 2026-07-04

## Status

Accepted

## Context

The original roadmap staged a simple verifier at MVP 3. The report-first design
approach (§6.9 of the spec) and the role of the verifier as trust anchor argue
for pulling it forward into v1. An earlier "MVP 0 fake report" milestone is
absorbed into the design process: the report is designed first and serves as the
primary artifact and the centerpiece of the README.

The v1 boundary is deliberately narrow. Features such as syslog reception, file
tailing, OTel, RFC 3161 anchoring, legal-hold policy, and qualified timestamps
are deferred to the roadmap recorded in ADR-0001.

## Decision

v1 (MVP 2 + verifier) delivers four components:

- **Local agent:** append-only spool, monotonic sequence, hash chain,
  heartbeat, client-side encryption, upload with retry/ACK/replay.
- **Central store:** persistence of encrypted segments, ACK, deduplication.
- **Verifier:** root reception, sequence and heartbeat gap detection,
  integrity/continuity report.
- **Markdown continuity report** matching the §6.9 example.

The verifier is promoted from MVP 3 to v1 because it acts as the trust anchor
(the entity that receives signed checkpoints outside the store operator's
perimeter).

## Consequences

**Positive.** Trust anchor ships with v1. Report-first design keeps the
Markdown output the primary user-facing artifact.

**Negative.** The verifier scope in v1 is narrow; extensions (eIDAS-qualified
timestamps, Rekor) are deferred to the roadmap in ADR-0001.

## References

- ADR-0001 — evidence and legal hardening roadmap (deferred items)
