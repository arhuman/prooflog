# 1. Evidence & legal hardening roadmap

Date: 2026-07-04

## Status

Accepted

## Context

A technical and legal gap analysis was run against the v0.2.0-dev codebase and
docs from four independent perspectives, two of them source-verified (internal
analysis, not versioned).

Two findings were unanimous across all four reviews and are treated as settled:

- **Prior art:** the closest functional equivalent is not a single product but
  the "good-enough" DIY stack — Vector/Fluent Bit disk buffer → mTLS →
  S3/MinIO/Azure Blob Object Lock → periodic hash manifest. Prooflog's
  differentiation (bundle + independent verifier + reports + honesty) is real but
  thin unless the boundary statements are explicit. Comparable managed systems:
  Azure Confidential Ledger and CloudTrail Lake; immudb and Guardtime KSI (the
  latter with actual courtroom precedent in Dutch courts). AWS QLDB is in full
  shutdown (2025-07-31) — a signal of how narrow the standalone-ledger niche is.
- **Legal:** the top blocker is the conflict between append-only immutability and
  GDPR Art. 17 / FADP Art. 32 right-to-erasure and data-minimization
  (Art. 5(1)(c)) — sharpened by the fact that envelope **metadata** (`actor`,
  `source_id`, event type, timing) is **not encrypted** and is chained
  permanently, so it can be neither erased nor minimized.

Prooflog's credibility rests on being honest about its limits; it is pre-alpha, and
its on-disk formats and gRPC APIs are still explicitly unstable. This is the
cheapest window to make format-level privacy changes. These constraints drive the
sequencing below.

## Decision

Adopt the following six-item remediation roadmap, ranked by impact ÷ cost and
sequenced so that cheap, high-signal items land first and the one format-breaking
item is done while formats are still fluid. Each item's rationale, cost, and
expected outcome are recorded in the internal analysis (not versioned).

1. **Positioning & boundary copy** (README section + FAQ). State "evidence
   continuity layer, not SIEM/WORM/GRC/qualified-timestamping"; pre-empt the
   "reinvented RFC 5848 syslog-sign" objection; state that Prooflog supplies
   incident *evidence* but does **not** satisfy NIS2 Art. 23 / CRA Art. 14 / NCSC
   *notification* duties; contrast against the DIY stack. Cost: <1 day.

2. **Report-liability hardening.** Embed tool version, verifier binary hash,
   algorithm IDs, input segment hashes, and checkpoint IDs in every report; adopt
   defensive wording ("verified against records available to the verifier"; "No
   gap detected ≠ no event was omitted before it reached the agent"). Cost:
   1–2 days.

3. **Data-residency guidance + attestable locality.** Publish a deployment matrix
   (same-jurisdiction / adequate / third-country-with-SCCs / no-go-without-review),
   make Store/Verifier locality configurable, and attest it as a report field.
   Addresses Schrems II / FADP Art. 16 exposure created by unencrypted metadata.
   Cost: 1–3 days.

4. **Metadata privacy model** (the #1 legal blocker). Treat envelope metadata as
   personal data: actor/source IDs as keyed HMAC with an erasable per-subject/
   tenant salt; move more fields under encryption; support per-subject payload
   keys instead of a single org-wide key; add a "privacy manifest" to reports.
   This is a deliberate on-disk format change, taken now while pre-alpha. Cost:
   1–2 weeks.

5. **Qualified-timestamp anchoring.** Implement the reserved `Anchor` interface
   with an RFC 3161 TSA client, then an eIDAS/ZertES qualified TSA; batch
   checkpoints. Moves evidence from self-signed (no legal presumption) toward the
   eIDAS Art. 41 timestamp presumption. Cost: ~1 week (RFC 3161 MVP) + provider
   account/fees.

6. **Enforceable + provable retention + legal-hold override.** Per-framework
   retention policy in the Store, sealed as a tamper-evident event; a legal-hold
   flag overriding expiry; a forensic search → decrypt → export workflow.
   Addresses SEC 17a-4 / CO Art. 958f / GoBD minimums and spoliation risk. Cost:
   1–1.5 weeks.

**Sequencing:** #1–#3 first (~4 days, copy/config); then #4 (format-fluid
window); then #5 and #6 as feature milestones. Total ~5–6 weeks, front-loaded.

## Scope boundaries (explicitly out of scope)

These remain the operator's responsibility and Prooflog will *not* claim to
provide them, only to produce evidence usable within them:

- Deciding whether an incident is reportable, or submitting/tracking NIS2/CRA/NCSC
  notifications (the 24h/72h/1-month cascade).
- Legal interpretation or a compliance guarantee for any framework.
- Native full-coverage collection for PCI-DSS Req. 10 or HIPAA — Prooflog's
  "critical-events-only" scope is a supplement to, never a substitute for, full
  logging in those regimes.

## Consequences

**Positive.** Removes the top EU/Swiss adoption blocker (#4) and the highest-ROI
credibility gaps (#1–#3) quickly; delivers two substantial feature milestones
(#5, #6); keeps the "honest about limits" posture intact by hardening report
wording and boundaries.

**Negative / cost.** #4 is a breaking on-disk format change; it must precede any
format freeze and will invalidate existing spools/segments generated before it.
#5 introduces an external dependency (a TSA) and recurring per-stamp cost for the
qualified tier. #6 adds a retention/policy engine surface to the Store that must
itself be tamper-evident, increasing Store complexity.

**Neutral.** Boundary statements (#1, scope section) narrow the project's
claims deliberately; this is consistent with the project's stated posture
(tamper-evident, not tamper-proof; evidence, not compliance).

## References

- Internal gap analysis (not versioned) — synthesized findings and the six
  recommendations with per-item why/cost/outcome.
- `docs/legal_protection.md` — threat/obligation mapping (T-1…T-12).
- `docs/standards.md` — requirements register (REQ-C/E/R); REQ-C-15 (anchoring
  interface), REQ-E-11 (retention), REQ-E-12/13 (syslog-sign / SEC 17a-4 prior
  art).
- `decisions.md` — settled v1 design decisions.
