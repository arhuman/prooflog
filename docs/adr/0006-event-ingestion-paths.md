# 6. Event ingestion paths

Date: 2026-07-04

## Status

Accepted

## Context

v1 operates in strict evidence-only mode (§9.4). Adding syslog reception, file
tailing, or OTel in v1 would blur the boundary between evidence collection and
general log aggregation, enlarge the attack surface, and obscure the primary use
case. Third-party integrations (Vector, Fluent Bit, GitHub Actions) are planned
as thin adapters on top of the HTTP path — they do not require a separate
ingestion protocol.

## Decision

Three ingestion paths and no others in v1:

- **CLI:** `prooflog event …`
- **HTTP:** `POST /v1/events` on the local agent
- **Stdin:** pipe

Syslog reception, file tailing, and OTel are explicitly out of scope for v1.
All planned third-party integrations will target the HTTP path.

## Consequences

**Positive.** Minimal attack surface. Clear boundary between evidence collection
and log aggregation. The HTTP path is the single extension point for all future
integrations, keeping the adapter model simple.

**Negative.** Operators who want to feed an existing log pipeline need an
adapter; none ships in v1.

## References

- ADR-0003 — v1 product scope
