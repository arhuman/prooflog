# Legal Protection — Threats, Obligations, and How Prooflog Addresses Them

This document lists the concrete threats to evidence that an operator of
regulated systems should address, the legal or normative obligations that
require addressing each one, and the mechanism by which Prooflog detects
or prevents it. Requirement IDs (REQ-C/REQ-E/REQ-R) refer to the register
in [standards.md](standards.md).

**Two honest caveats frame everything below.** First, Prooflog is
*tamper-evident*, not *tamper-proof*: following the Common Criteria
FAU_STG.2 "detect" posture, it makes tampering **detectable**, it does
not make it **impossible**. Second, Prooflog **helps produce technical
evidence** usable in regulated contexts; it does not, by itself, make an
organization compliant with any regulation — in particular, it never
decides whether an incident is reportable, never submits a notification,
and never tracks the NIS2 Art. 23 / CRA Art. 14 / Swiss ISA reporting
cascades (see [What Prooflog is — and is
not](../README.md#what-prooflog-is--and-is-not) for the full boundary
statement). The detection guarantees also
assume the recommended deployment (a Verifier operated by a party
independent of the Store operator); a fully self-hosted
deployment where one administrator controls the agent, the store, and the
verifier can rewrite history undetected, and reports generated from such a
deployment state this limitation.

---

## T-1 — The attacker modifies a log entry already in central storage.

**Legal impact if unaddressed**
- **ISO/IEC 27001 A.8.15** and **NIS2 IR 2024/2690 §3.2.5** require logs to be protected against modification; silent alteration is a direct control failure.
- **Common Criteria FAU_STG.2** requires detection of unauthorized modification of stored audit records.
- **RFC 3227 / ISO/IEC 27037**: altered records are neither *authentic* nor *reliable*, so the evidence is inadmissible or worthless in an audit or proceeding.
- **DORA RTS 2024/1774 Art. 12** requires log data to be secured against tampering for financial entities.

**How Prooflog addresses it** — Each record's `event_hash` is computed over its exact stored bytes (REQ-C-04, REQ-C-03) and chained via `prev_hash` (hash chain), and every segment is sealed under an RFC 6962 Merkle root signed with Ed25519 (REQ-C-01, REQ-C-05, REQ-C-06). Any byte changed in storage breaks the recomputed hash, the chain link, and the signed root, so the verifier flags it as a hash/chain finding (REQ-E-05, REQ-E-08).

## T-2 — The attacker deletes an event already accepted by the system.

**Legal impact if unaddressed**
- **NCSC / ISA (Art. 74e)** and **NIS2 Art. 23** incident reports depend on a complete timeline; a removed event silently corrupts the reconstruction.
- **LPD/OPDo Art. 15(5–6)** and **GDPR Art. 33(5)** require a complete, retained record of a breach; deletion defeats the retention duty.
- **RFC 3227**: the evidence is no longer *complete*.

**How Prooflog addresses it** — Every source assigns a strictly monotonic sequence number before send (REQ-E-07); a missing number (…1841, 1843…) proves event 1842 was accepted but is now absent. The hash chain compounds this: a deletion also breaks `prev_hash` continuity. The limitation is explicit — only events accepted by the agent (or reserved by the intent/result protocol) can be proven missing.

## T-3 — The attacker reorders events to disguise the true sequence of actions.

**Legal impact if unaddressed**
- **NCSC 24h / CRA Art. 14 / NIS2 Art. 23** timelines must reflect true ordering to establish root cause and the "who did what, when" of an incident.
- **RFC 3227 / NIST SP 800-86**: reordered evidence is unreliable for forensic analysis.

**How Prooflog addresses it** — Ordering is fixed by the monotonic sequence number and the `prev_hash` linkage, not by timestamps (REQ-C-13, REQ-E-07); reordering breaks the chain. The Merkle leaf position is bound to the sequence, so a reordered leaf changes the signed root (REQ-C-01, REQ-C-09).

## T-4 — The attacker inserts a fabricated event retroactively into the past.

**Legal impact if unaddressed**
- **SEC 17a-4 / FINRA 4511** audit-trail requirements and **FAU_STG.2** exist precisely to detect after-the-fact insertion.
- **RFC 3227 / ISO/IEC 27037**: a back-dated record destroys *authenticity* and the chain of custody.

**How Prooflog addresses it** — A naive retroactive insert must recompute every subsequent hash and re-sign every affected segment, which fails against checkpoints the independent verifier already received and countersigned in real time (REQ-C-07, REQ-C-02). Consistency verification between successive checkpoints exposes any history that is not a pure append of the previously sealed one.

## T-5 — A network outage causes events to be silently lost before they reach storage.

**Legal impact if unaddressed**
- **NIS2 IR 2024/2690 §3.2** and **NIST SP 800-92 §5.1.2** require reliable log collection; a silent gap is an observability failure an auditor will challenge.
- **NCSC / CRA**: "we lost the logs during the incident" undermines the mandatory report.

**How Prooflog addresses it** — The local agent writes every accepted event to a durable append-only spool, fsynced before acknowledgement, and continues during outages (REQ-E-04, REQ-E-03); on reconnection it replays from the last ACKed offset, bracketing the gap with `system.network_outage` and `system.replay_completed` events. The transport section of the continuity report proves buffered events were replayed with zero loss.

## T-6 — A source stops logging, creating an unobserved window that nobody notices.

**Legal impact if unaddressed**
- **ISO/IEC 27001 A.8.16** requires monitoring; **NIS2 IR 2024/2690 §3.2.3** requires log start/stop events to be recorded.
- **NCSC / LPD**: an undetected blind period means an incident could have occurred with no evidence and no notification — the worst regulatory outcome.

**How Prooflog addresses it** — A signed heartbeat proves the source was alive and able to log at each interval (REQ-E-06); a silence beyond the policy is reported as a bounded observation gap, and clean shutdowns/restarts (`system.agent_stopped` / `system.agent_started`) bound the window. Timestamp alone cannot prove a loss of observability — the heartbeat can.

## T-7 — The central storage operator reads sensitive payload data they should not see.

**Legal impact if unaddressed**
- **LPD/OPDo, GDPR** data-minimization and confidentiality: centralizing readable personal or sensitive data at a processor expands breach exposure and may itself be a violation.
- **NIS2 / DORA** confidentiality-of-logs expectations.

**How Prooflog addresses it** — Business payloads are encrypted client-side with age (ChaCha20-Poly1305, single-use per-event file keys) for an organization-held X25519 recipient key that is never uploaded (REQ-C-08, REQ-C-11); the store and the verifier hold only ciphertext, hashes, and minimal envelope metadata. The wording is deliberately "client-side encrypted with minimal metadata disclosure", not "zero-knowledge" — frequency, size, source, type, and timing metadata remain visible.

## T-8 — The attacker truncates the log or rolls it back to an earlier state.

**Legal impact if unaddressed**
- **FAU_STG.2 / SEC 17a-4**: dropping the most recent records is a form of undetected deletion the audit-trail requirements target.
- **NCSC / CRA / DORA**: truncation can erase exactly the incident window that must be reported within 24/72 hours.

**How Prooflog addresses it** — The verifier persists every checkpoint append-only and enforces the C2SP rule that it will never accept a checkpoint inconsistent with one it already holds; a shrunk tree size (rollback) or a divergent root at the same size (truncation) is rejected with a structured fork finding at submission time (REQ-C-07, REQ-C-02). This submission-time check is the v1 trust-anchor behavior.

## T-9 — The attacker manipulates timestamps to misrepresent when something happened.

**Legal impact if unaddressed**
- **NCSC 24h, CRA 24h/72h, NIS2, DORA, FINMA** deadlines all run from a discovery/occurrence time; a falsified time defeats the reporting clock and any proof of timeliness.
- **ISO/IEC 27001 A.8.17** requires synchronized, trusted time sources.
- **eIDAS Art. 41**: only a qualified timestamp carries a legal presumption of time accuracy.

**How Prooflog addresses it** — Timestamps use one pinned RFC 3339 UTC byte format inside the hashed record (REQ-C-13), and agents record their time source and clock-drift metadata in heartbeats so the report can attest time-source trust (REQ-E-06). The signed checkpoints received continuously by the independent verifier bound each event between two externally-witnessed times. Full legal-grade time is a documented roadmap item via the pluggable `Anchor` interface (RFC 3161 qualified TSA / Rekor, REQ-C-15).

## T-10 — An attacker steals an agent's signing key and forges events.

**Legal impact if unaddressed**
- **NIST SP 800-57** key-management and **ISO/IEC 27001** expect key-compromise handling; forged-but-valid events poison the evidence base.
- **RFC 3227**: authenticity of the source is compromised.

**How Prooflog addresses it** — Signing keys are per-agent, private to the host, and separate from the encryption recipient key (REQ-C-11). A compromised key lets an attacker forge *new* events from that source going forward; it does **not** let them rewrite past events already sealed into checkpoints the verifier holds. Compromise is handled by a `system.key_revoked` event (which surfaces as an `F-KEYREV` finding naming the exposure window) plus a `system.key_rotated` re-key. Rotation seals the handoff under the outgoing key and continues the Merkle tree unbroken, so the rotated chain still verifies clean; the honest, documented caveat is that events between compromise and revocation are suspect (REQ-C-12).

## T-11 — The store shows different histories to different auditors (equivocation / fork).

**Legal impact if unaddressed**
- **RFC 3227 / ISO/IEC 27037**: a log that can present two truths has no evidentiary value and no reliable chain of custody.
- **FAU_STG.2**: undetected divergence is an integrity failure.

**How Prooflog addresses it** — Because the verifier is operated independently of the store and holds the single append-only checkpoint history per source, two divergent roots for the same source and size are detected as a fork (REQ-C-07). This is the separation-of-powers that makes the guarantee meaningful — and the reason the self-hosted single-admin caveat is stated wherever it applies.

## T-12 — A local segment is rewritten on disk before it is sealed and uploaded.

**Legal impact if unaddressed**
- **NIST SP 800-92 §5.1.3** requires append-only local log write access and protected generation.
- **RFC 3227**: pre-sealing tampering breaks integrity at the point of collection.

**How Prooflog addresses it** — The spool is append-only and each frame stores the record bytes with their hash; files are fsynced before the event producer is acknowledged and sealed files are never reopened for writing (REQ-E-04, REQ-E-09). This narrows the pre-sealing window; the residual exposure (an attacker with host access before the first upload) is the honest boundary that external anchoring on the roadmap (REQ-C-15) further reduces.

---

## Summary mapping

| Threat | Primary Prooflog mechanism | Key obligations served |
|--------|---------------------------|------------------------|
| T-1 modify stored entry | hash chain + signed Merkle root | ISO 27001 A.8.15, NIS2 §3.2.5, FAU_STG.2, DORA Art. 12 |
| T-2 delete accepted event | monotonic sequence + chain | NCSC, NIS2 Art. 23, LPD/GDPR retention |
| T-3 reorder events | sequence-bound chain + Merkle position | NCSC, CRA, NIS2, SP 800-86 |
| T-4 retroactive insert | continuous signed checkpoints + consistency | SEC 17a-4, FAU_STG.2, ISO 27037 |
| T-5 silent loss on outage | durable spool + replay + outage bracketing | NIS2 §3.2, SP 800-92 |
| T-6 unobserved window | signed heartbeats + start/stop events | ISO 27001 A.8.16, NIS2 §3.2.3 |
| T-7 operator reads payloads | client-side age encryption, org-held key | LPD/OPDo, GDPR, NIS2/DORA |
| T-8 truncation / rollback | append-only checkpoint enforcement | FAU_STG.2, SEC 17a-4, CRA/DORA |
| T-9 timestamp manipulation | pinned time + clock metadata + anchoring | NCSC/CRA/NIS2/FINMA clocks, A.8.17, eIDAS |
| T-10 stolen agent key | per-host keys + revocation events | SP 800-57, ISO 27001, RFC 3227 |
| T-11 equivocation / fork | independent verifier, single checkpoint history | RFC 3227, ISO 27037, FAU_STG.2 |
| T-12 pre-sealing rewrite | append-only fsynced spool | SP 800-92 §5.1.3, RFC 3227 |

---

## Beyond tampering — retrofitting a missing capability onto a mandated tool

The threats above assume the evidence exists and someone might alter it.
A different failure mode is just as damaging in front of a regulator: a
tool the organization is required to use — or cannot realistically
replace — simply lacks a capability the applicable rules assume, and the
organization inherits the gap. Prooflog can supply the missing
capability as a sidecar, without touching the tool itself.

### Worked example — the identity provider that retains logs for weeks, not years

Sign-in and administrative audit logs from a managed identity provider
are among the first artifacts requested in any incident investigation or
audit: they answer "who authenticated, from where, and who changed the
access rules." Yet several widely deployed managed identity providers
retain these logs for only 30–90 days — as little as 7 days on
entry-level tiers — with no contractual option to extend retention
inside the product.

**Legal impact if unaddressed**
- **PCI DSS v4.0 Req. 10.5.1** requires at least 12 months of audit log history, with the most recent three months immediately available.
- **NIS2 IR 2024/2690 §3.2** expects logs to be retained for a predefined period consistent with incident detection and response; **DORA RTS 2024/1774 Art. 12** requires financial entities to define and enforce log retention adequate for their supervisory and investigative needs.
- **SEC 17a-4 / FINRA 4511** impose multi-year record retention on regulated broker-dealers; several national data-retention regimes require one year for connection data.
- Practically: intrusions are routinely discovered months after initial access. When the mandatory report or the forensic reconstruction is due, the vendor window has long since closed — "the IdP no longer has the logs" is the organization's failure, not the vendor's.

**How Prooflog adds the missing capability** — A small collector pulls
the tool's log-export API (or receives its event feed) well within the
vendor's retention window and hands each entry to the local Prooflog
agent through its standard ingestion paths (CLI, HTTP, stdin). From the
moment of ingestion, each upstream entry is a first-class evidence
record: hashed over pinned bytes, sequence-numbered, chained, sealed
under a signed Merkle root, client-side encrypted, and retained under
the **operator's** retention policy — with legal-hold and forensic-export
support — instead of the vendor's. Retention duration stops being a
property of the mandated tool and becomes a property of the evidence
pipeline the organization controls.

**The honest boundary** — Prooflog attests integrity and continuity
*from ingestion onward*. It cannot prove the upstream export was
complete: sequence numbers and heartbeats guarantee that nothing was
lost after the collector accepted an entry, not that the vendor emitted
every entry it should have. Timeliness is part of the design: if the
collector is down for longer than the vendor's retention window, the
missed entries are unrecoverable — heartbeats and outage bracketing
(T-5, T-6) will bound and disclose that window in the report, but cannot
fill it. The defensible claim in an audit is therefore precise: "we hold
a tamper-evident, independently verifiable copy of every entry the tool
exposed to us, retained for the legally required duration" — not "we
hold everything the tool ever knew."

### The general pattern

The same construction retrofits other missing capabilities onto legacy
or mandated tools: tamper-evidence for a tool whose logs are mutable
files (T-1), provable ordering for a tool without counters (T-3),
confidential centralization for a tool that only writes plaintext
locally (T-7). The tool remains authoritative for *what happened*;
Prooflog becomes authoritative for *what the tool said — and that nobody
changed it afterwards*.
