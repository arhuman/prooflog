# 8. Assurance tiers and the assess mode

Date: 2026-07-05

## Status

Accepted

## Context

Prooflog verifies evidence it captured itself: signed, chained, checkpointed
records. A recurring operational need (internal notes, not versioned) is to run
prooflog's continuity analyzers over an organization's *existing* logs — an IdP
sign-in export, an S3/CloudTrail archive, an immudb dump — and report what
those logs can and cannot prove. This is the "initial audit" deliverable: it
demonstrates, on the organization's own data, what its logs can and cannot
prove, and motivates deploying agents for capture-time guarantees.

Analysing foreign data is valuable but evidentiarily different from verifying
captured evidence. Sequence numbers and heartbeats in an unsigned export are
only as trustworthy as the pipeline that produced them; no analysis can
retroactively confer capture-time guarantees. A report that blurred the two
would destroy the honesty posture prooflog is built on (REQ-E-01,
REQ-E-08). We need one explicit scale that keeps them distinct.

## Decision

**Assurance tiers.** Every report carries an `evidence.AssuranceTier`:

- **Tier 0 assessed** — findings over foreign, unsigned data. Analytical only.
- **Tier 1 captured** — prooflog-captured evidence, self-hosted anchor, no
  separation of powers (today's `SelfHosted=true`).
- **Tier 2 verified** — captured evidence verified by an anchor independent of
  the store operator.
- **Tier 3 witnessed** — verified and externally witnessed (C2SP witness
  cosigning or a qualified timestamp anchor). Forward-compatible with the
  roadmap; its derivation rule lands with those features.

The continuity report derives its tier from the existing trust disclosure
(`DeriveTier`); the assess path sets Tier 0 explicitly.

**Assess mode.** A new `internal/assess` package and `prooflog assess`
subcommand consume foreign data as JSONL plus a mapping profile, run only the
analyzers the input's capabilities support, and emit an "Evidence Assessment
Report" whose document identity is visibly distinct from the continuity report.

**Finding namespace.** Probative findings keep `F-*`; assess findings use
`A-*` (`A-SEQGAP`, `A-DUP`, `A-HBGAP`, `A-TIME`, `A-COVERAGE`, `A-INPUT`). A
reader cannot confuse the two grades by ID alone, and a Tier 0 document never
contains an `F-*` id.

**Document identity.** Tier 0 renders as "Evidence Assessment Report" with an
unmissable banner stating nothing is attested; no verification certificate is
ever produced below Tier 1.

**Default input caps.** `prooflog assess` reads are bounded by default:
`--max-bytes` 4 GiB and `--max-records` 10,000,000. The input is a foreign,
untrusted export, so the default invocation must not be exhaustible by an
oversized dump or a decompression bomb. Hitting a cap is always loudly
disclosed — a stderr warning plus an unmissable report banner (REQ-E-16); there
is no silent truncation. Passing `0` is the operator's explicit opt-out to an
unlimited read; the `internal/assess` library default (`assess.Read`) stays
unlimited.

## Consequences

**Positive.** The initial-audit capability ships without weakening any existing
guarantee. The tier foundation also serves the hosted-verifier (caveat-free
Tier 2 reports) and qualified-anchor (Tier 3) roadmap. Read-side
interoperability (report from data resting in S3, immudb, etc.) is delivered by
a generic JSONL+profile input, with no per-storage read drivers.

**Negative.** A second report document type and renderer to maintain. Mixed
per-source tiers in one report require the global verdict to be stated per-tier,
never blended.

**Non-goals (v1).** No verification of foreign proof formats (CloudTrail
digests, immudb inclusion proofs — recorded in provenance, not evaluated); no
storage read drivers; no queries, dashboards, or log analytics. Each would be
the volume/SIEM anti-goal (ADR-0003 scope) in a new coat.

## References

- ADR-0003 — v1 product scope (anti-goals)
- Internal notes (not versioned) — initial-audit engagement shape and build plan
