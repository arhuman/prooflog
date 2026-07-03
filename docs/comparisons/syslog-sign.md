# Prooflog vs signed syslog (RFC 5848)

RFC 5848 had the same primitives circa 2010 — signed log batches, sequencing,
missing-message detection — and it failed for a reason worth stating: in-band
signature blocks broke under relay truncation and UDP size limits, so the
ecosystem converged on transport security, which protects logs in transit but
not at rest. Prooflog seals **above transport, at rest**: encrypted payloads,
RFC 6962 Merkle proofs, C2SP checkpoint fork rejection by an independent
verifier, a durable local spool, heartbeats, and auditor-readable reports —
none of which syslog-sign had. The at-rest/continuity gap it left open is
precisely the niche this tool occupies.
