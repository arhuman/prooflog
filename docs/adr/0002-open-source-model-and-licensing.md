# 2. Open-source model and permissive licensing

Date: 2026-07-04

## Status

Accepted

## Context

Prooflog is a credibility and trust tool: operators must be able to audit every
component before placing evidence in its chain. Open-core splits or copyleft
licenses (AGPL, BSL) would restrict self-hosting and create friction for
operators who need full code visibility. A permissive license also keeps the
project compatible with the widest range of enterprise deployment policies.

## Decision

MIT license for all components: agent, central store, verifier, and report
generator. No open-core split, no AGPL, no BSL. Every component is
self-hostable end to end.

## Consequences

**Positive.** Operators can audit, fork, and self-host without legal friction.
No artificial feature gates force a commercial dependency.

**Negative.** No license-based exclusivity; differentiation must come from
hosted service quality, qualified-timestamp integrations, and support — not
from withholding code.

## References
