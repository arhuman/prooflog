# 7. Core technology stack

Date: 2026-07-04

## Status

Accepted

## Context

Technology choices must serve the needs of a tamper-evident evidence tool, not
be cargo-culted. The deployment model — a single operator running all three
components — favors operational simplicity: zero external database dependencies,
a single auditable binary, and a standard RPC layer. Documentation language is
fixed because the codebase, standards references (RFCs, C2SP), and target
audience are uniformly English.

## Decision

**Language and binary**
- Go; single static binary (`prooflog`, CGO_ENABLED=0) with subcommands:
  `agent`, `store`, `verifier`, `verify`, `report`, and supporting commands
  (`event`, `init`, `actor`, `hold`, `export`).
- Demo docker-compose for local development and evaluation.

**Transport**
- gRPC for agent → store communication (§8.2).
- HTTP/JSON as the local facade for event ingestion.

**Persistence**
- SQLite index + filesystem blobs for the central store; zero external database
  dependency.

**Operational defaults**
- Heartbeat interval: 60 s default, configurable per agent.

**Vocabulary constraint**
- Use "client-side encrypted", never "zero-knowledge" (§ risk 3 in docs). The
  distinction matters for threat-model honesty and legal claims.

**Documentation language**
- All documentation in English (settled 2026-07-04).

## Consequences

**Positive.** Single static binary simplifies deployment, auditing, and
packaging. SQLite + blobs requires no database server, eliminating an entire
dependency class. gRPC gives a typed API and streaming capability. English
documentation aligns with the standards citations that underpin the legal
credibility of evidence.

**Negative / constraints.** CGO_ENABLED=0 is required for true static linking;
enforced in the Makefile build target. SQLite limits write concurrency at very
high ingestion rates — not a concern for v1 evidence-only scope (critical events
only, not full log streams).

## References

- ADR-0004 — cryptographic construction (vocabulary constraint rationale)
- ADR-0006 — event ingestion paths (HTTP/JSON facade)
- `Makefile` — enforces CGO_ENABLED=0 and build flags
