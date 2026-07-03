# Data Residency — Deployment Guidance

Prooflog's topology is inherently distributable: the Agent runs on the source
host, the Store and the Verifier can each run anywhere. **Where they run is a
legal decision, not just an operational one**, because Prooflog moves personal
data across whatever borders sit between its components.

## Why this matters even with encrypted payloads

Business payloads are encrypted client-side and never readable by the Store or
the Verifier. But the **envelope metadata is not encrypted**: `source_id`,
sequence numbers, event types, timestamps, outcome, and the actor field travel
in plaintext to the Store, and roots/sequences/heartbeats to the Verifier.
Wherever that metadata identifies or can indirectly identify a natural person —
an admin username in `actor`, a person-linked workstation in `source_id` — it
is personal data under GDPR Art. 4(1) and the Swiss FADP, and its transfer
abroad falls under GDPR Chapter V (Art. 44 ff.) or FADP Art. 16–17.

The planned metadata privacy model (pseudonymous actors with erasable
per-subject salts, labels folded into the encrypted payload — ADR 0001, item 4)
**reduces** this exposure but does not eliminate it: pseudonymized data
transferred together with the means of re-identification remains personal data,
and `source_id` stays plaintext by design.

Until then, and as standing hygiene:

> **Do not embed personal identifiers in source IDs, actor fields, labels, or
> event types.** Source IDs name infrastructure (`vps-01/api`), not people.

## Deployment matrix

Placement is evaluated separately for the **Store** (sees all envelope
metadata + ciphertext) and the **Verifier** (sees roots, sequences,
signatures, heartbeat timing — less data, still timing/identity metadata).

| Component placement | Legal posture | Guidance |
|---|---|---|
| Same jurisdiction as the data exporter (e.g. Swiss org, Swiss-hosted Store and Verifier) | No cross-border transfer | Cleanest default. Recommended for Swiss para-public / research deployments. |
| Country with an adequacy decision (e.g. Swiss org → EU/EEA host; EU org → Swiss host) | Transfer permitted under the adequacy decision (GDPR Art. 45 / FADP Art. 16(1)) | Acceptable. Record the adequacy basis in your processing register. |
| Third country **with** safeguards (SCCs / FADP standard clauses + transfer impact assessment) | Transfer permitted only with supplementary measures assessed post-Schrems II | Requires legal review: TIA, SCCs with the host, assessment of the destination country's lawful-access regime. The verifier-only case is easier to justify (less data) but is not exempt. |
| Third country **without** safeguards | Not permitted for personal-data metadata | **No-go without legal review.** Do not point an agent at a Store in such a jurisdiction. |

Additional considerations:

- **Hosted Verifier as a service.** A third-party verifier operator (a hosted
  Verifier service) receives roots, signatures, sequence numbers, and
  heartbeat timing — never payloads. Its jurisdiction and its support-access
  paths (who can log in, from where) enter the same matrix.
- **Backups and spool copies.** The agent's local spool and the salt store
  (once the privacy model ships) contain the most sensitive material on the
  source host. Backups that ship them to another jurisdiction are themselves
  transfers.
- **Support access is a transfer.** A Store hosted in-country but administered
  from a third country gives that third country's staff access to the metadata;
  post-Schrems II practice treats this as a transfer-relevant fact.

## Declaring locality

The Store and Verifier accept a `--locality` declaration (e.g. `CH`, `EU/DE`),
and `prooflog report` records it in the report header. This is an
**operator declaration, not a cryptographic proof** — the report says so
explicitly. Its purpose is chain-of-custody documentation: the operator states
where evidence was stored and verified, and signs that statement as part of
the report.

Prooflog does not and cannot enforce residency technically; it makes the
declaration explicit, attestable, and part of the tamper-evidenced record.
