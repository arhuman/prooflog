# Prooflog

**Prooflog is a cryptographic evidence-continuity layer for security-critical events.**

Prooflog records deployments, access changes, incident milestones, and backup tests into a cryptographically chained, client-side encrypted log. Each source signs and chains its own events; events buffer locally across outages and replay automatically when the store returns. An independent verifier detects missing events, rewritten history, heartbeat gaps, clock drift, and store/agent divergence.

Prooflog is not a SIEM, not log search, not WORM storage, not a compliance guarantee. It answers one narrow question: *Can we prove this critical event timeline was observed, ordered, preserved, and not silently rewritten?*

> **WORM proves nothing was deleted. A ledger database proves nothing was changed. Prooflog proves nothing is missing.**

---

## See it break

```
$ prooflog demo tamper

== baseline verification (pristine evidence) ==
  VERDICT: clean — no findings.
baseline is clean — now we attack it.

== tampering #1 — altered one recorded event → hash chain broken ==
  verifier findings:
    [high] F-CHAIN: hash chain broken
    [high] F-FORK: checkpoint inconsistency
  ✓ detected (verify exited non-zero)

== tampering #2 — excised recorded events from the spool → sequence gap / chain break ==
  verifier findings:
    [high] F-CHAIN: hash chain broken
    [high] F-FORK: checkpoint inconsistency
  ✓ detected (verify exited non-zero)

== tampering #3 — truncated the log to hide the latest events → caught by the independent checkpoint ==
  verifier findings:
    [high] F-FORK: checkpoint inconsistency
  ✓ detected (verify exited non-zero)

== tampering #4 — rewrote a signed checkpoint → invalid signature + fork rejected ==
  verifier findings:
    [high] F-FORK: checkpoint inconsistency
    [high] F-SIG: invalid checkpoint signature
  ✓ detected (verify exited non-zero)

== summary ==
  4 tampering attempts, 4 detected.
```

Tampering #3 is the one a local hash script cannot catch: the truncated log still verifies as an internally valid chain on disk, but the independent signed checkpoint proves records are missing.

`prooflog demo healthy` and `prooflog demo outage` show the clean and outage-recovery paths.

Fuller narrated walkthrough: `bash scripts/demo.sh` (builds from source, generates keys, runs all three services, simulates outage and recovery).

See [`examples/continuity-report.md`](examples/continuity-report.md) for the shape of the report output.

---

## How it works

```
events (CLI / POST /v1/events / stdin)
        │
        ▼
┌─────────────────┐   gRPC (mTLS)   ┌─────────────────┐
│ Agent            │ ───────────────▶│ Store            │
│ seq · chain ·    │  segments+ACK   │ blobs · index ·  │
│ spool · seal ·   │                 │ dedup · ACK      │
│ heartbeat        │                 └────────┬────────┘
└────────┬────────┘                           │ pull: segments
         │ checkpoints (signed notes)         ▼
         └──────────────────────────▶┌─────────────────┐
                                     │ Verifier         │
                                     │ consistency ·    │
                                     │ gaps · findings ·│
                                     │ reports          │
                                     └─────────────────┘
```

**Agent.** Runs on the source host. Assigns a monotonic sequence number to each event and builds a per-source hash chain over the exact bytes stored on disk. Records group into segments; at each seal the agent emits a C2SP tlog-checkpoint signed with its Ed25519 key. Business payloads are age-encrypted (ChaCha20-Poly1305) before leaving the host; the org X25519 private key never touches the network. When the store is unreachable, events write to a local spool and retry with exponential backoff; outage windows are bracketed with `system.network_outage` and `system.replay_completed` events.

**Store.** Receives encrypted segments from agents over gRPC and persists them to a SQLite index and a blob directory. ACKs only after fsync. Deduplicates segments on replay by (source, sequence range, Merkle root). Never holds decryption keys and cannot read event payloads.

**Verifier.** Operates separately from the store. Accepts signed checkpoints directly from agents and enforces the append-only rule: any checkpoint inconsistent with a previously accepted one is rejected (fork rejection, REQ-C-07). Pulls raw segment bytes from the store, recomputes every leaf hash and Merkle root using RFC 6962, and confirms they match agent checkpoints. Detects sequence gaps, heartbeat gaps, agent/store divergence, and clock drift. In v1, the verifier is the trust anchor and is intended to run under a separate administrative authority from the store operator.

---

## What it is — and is not

**Not a SIEM.** No search, no correlation, no alerting. Prooflog answers one question a SIEM does not: can you prove this list of events is complete and unmodified? Keep your SIEM; feed Prooflog the few events you may one day have to prove.

**Not WORM storage.** Object Lock prevents object deletion but proves nothing about the order or continuity of events inside it, and nothing about events lost before the write. Prooflog is tamper-evident (Common Criteria FAU_STG.2 "detect" posture), not tamper-proof, and pairs well with WORM storage underneath.

**Not a GRC tool.** Vanta, Drata and their peers aggregate evidence from APIs they trust. Prooflog creates evidence verifiable on its own terms; a Prooflog report is an input to a GRC workflow, not a replacement.

**Not qualified timestamping.** Checkpoints are self-signed. The verifier can anchor them to an RFC 3161 TSA (`prooflog verifier --tsa-url`), which proves existence-at-time, but until an eIDAS-qualified TSA is configured the anchors carry no legal time presumption. A qualified electronic timestamp (eIDAS Art. 41) is the only construct that carries a legal presumption of time accuracy; Prooflog is designed to attach one, not to imitate one.

**Not an incident-notification system.** Prooflog helps prove what you knew and when; it never decides whether an incident is reportable, never identifies the competent authority, never submits a notification, and never tracks reporting deadlines — the NIS2 Art. 23 24h/72h/one-month cascade, the Swiss NCSC 24h-plus-14-days obligation, or CRA Art. 14. Those duties remain with the operator and their counsel.

---

## Why not just…

A competent engineer can assemble Vector or Fluent Bit (disk buffer) → mTLS → S3/MinIO Object Lock in a day. Honest comparison:

| | DIY pipeline + Object Lock | Prooflog |
|---|---|---|
| Scale, search, ecosystem | **Wins** — mature collectors, dozens of sinks | Out of scope by design |
| WORM retention / legal hold | **Wins** — real retention modes today | Policy-driven retention with tombstones + legal holds (WORM storage still recommended underneath) |
| Per-record hash chain | No | Yes — deletion/reorder/insertion detectable |
| Independent verification | No — the storage admin is the trust root | Yes — fork-rejecting verifier outside the store operator |
| Continuity proof | Delivery is buffered, but gaps are silent | Heartbeats + bounded observation windows, gaps are findings |
| Payload confidentiality from the operator | No — operator reads plaintext | Client-side age encryption; store is blind |
| Evidence report | Build it yourself | Signed report stating proven vs not provable |

If it needs search, send it to your SIEM. If it may need proof, send it to Prooflog.

For the RFC 5848 / signed-syslog question: [`docs/comparisons/syslog-sign.md`](docs/comparisons/syslog-sign.md).

---

## Standards

Prooflog uses standard primitives: SHA-256 hash chains and RFC 6962 Merkle trees, Ed25519-signed C2SP checkpoints, age-compatible client-side encryption, and optional RFC 3161 timestamp anchoring. Full requirements register and per-module traceability: [`docs/standards.md`](docs/standards.md).

The C2SP checkpoint format is bit-compatible with the Go module transparency log ecosystem (Go sumdb, sigsum, Rekor). Third-party tools that understand C2SP checkpoints can verify Prooflog chains without modification.

Age-encrypted payloads decrypt with the standard `age` CLI using the org identity, making payload recovery independent of Prooflog tooling.

---

## Threat model

Prooflog is tamper-evident, not tamper-proof (Common Criteria FAU_STG.2 "detect" posture). Detection requires an independent verifier that received signed checkpoints from agents before any tampering occurred. When one administrator controls all three components, that administrator can rewrite history undetected; reports generated from such a deployment say so in the header.

Read the full threat model before trusting any report: [`docs/threat-model.md`](docs/threat-model.md).

---

## Assurance tiers

Prooflog grades the assurance behind its findings on an explicit four-tier scale, so a report never overstates what it proves ([ADR-0008](docs/adr/0008-assurance-tiers-and-assess-mode.md)):

- **Tier 0 — assessed.** Analytical findings over foreign, unsigned logs via `prooflog assess`. Indicative only; nothing is cryptographically attested.
- **Tier 1 — captured.** Evidence recorded through a Prooflog agent — signed, chained, checkpointed — but anchored within a single administrative domain.
- **Tier 2 — verified.** Captured evidence checked by a verifier operated independently of the store operator. This is the level at which the continuity guarantees hold against an insider.
- **Tier 3 — witnessed.** Verified and additionally witnessed by C2SP cosigning or a qualified timestamp anchor. On the roadmap.

`prooflog assess` reports state Tier 0 in their header. Tiers 1 and 2 correspond to the self-hosted and independently-verified deployments described in the threat model above; Tier 3 is on the roadmap.

---

## Regulatory context

Prooflog produces technical evidence usable in regulated contexts (Swiss ISA/NCSC, NIS2, CRA, GDPR/FADP). It does not certify or guarantee compliance.

Full details, including data residency considerations: [`docs/regulatory-context.md`](docs/regulatory-context.md).

---

## Install and build

**Requirements:** Go 1.26 or later. The binary is statically compiled with no cgo and no external runtime dependencies.

```bash
git clone https://github.com/arhuman/prooflog
cd prooflog
make build        # produces bin/prooflog
make test         # run the test suite
```

### CLI commands

| Command | Description |
|---|---|
| `prooflog init` | Generate org and agent keys; write a config skeleton |
| `prooflog agent` | Run the local agent daemon (ingest, spool, upload, heartbeat) |
| `prooflog store` | Run the Store service |
| `prooflog verifier` | Run the Verifier (independent witness / trust anchor) daemon |
| `prooflog event <type>` | Send a typed event to the running agent |
| `prooflog actor` | Manage actor pseudonyms: print or erase linkability |
| `prooflog key rotate\|revoke` | Rotate or revoke the agent signing key over the owner-only control socket |
| `prooflog hold` | Place, release, or list legal holds on the Store |
| `prooflog export` | Export a forensic evidence bundle with a signed custody manifest (`export verify` re-verifies a bundle offline) |
| `prooflog heartbeat` | Force an immediate heartbeat |
| `prooflog verify` | Offline-verify a spool or store pull; exits 1 on findings |
| `prooflog report` | Generate the Markdown continuity/integrity report (`report verify` checks a signed report's footer signature) |
| `prooflog assess` | Tier 0 assessment over foreign logs (JSONL + profile); exits 1 on findings |
| `prooflog demo [healthy\|outage\|tamper]` | Run the adversarial demo (default: tamper) |
| `prooflog spool cat <dir>` | Pretty-print spool frames for inspection |
| `prooflog version` | Print the build version |

Run `prooflog <command> -h` for per-command flags.

### Quickstart

```bash
# 1. Generate org and agent keys, write config.json.
#    The org identity (X25519) is printed once and never stored — back it up offline.
prooflog init \
  --dir ./demo \
  --org acme \
  --source-id vps-01/api \
  --store-addr 127.0.0.1:9700 \
  --verifier-addr 127.0.0.1:9800

# 2. Start the store.
# --insecure skips TLS and --allow-unauthenticated skips mTLS gating on privileged
# RPCs (segment upload, checkpoint, legal holds). Both are for this loopback demo
# only; TLS + mTLS client auth are the default for production use.
prooflog store \
  --dir ./demo/store-data \
  --listen 127.0.0.1:9700 \
  --insecure \
  --allow-unauthenticated &

# 3. Start the verifier (run this on independent infrastructure for meaningful assurance).
prooflog verifier \
  --listen 127.0.0.1:9800 \
  --store-addr 127.0.0.1:9700 \
  --data-dir ./demo/verifier-data \
  --keys ./demo/verifier-keys.json \
  --insecure &

# 4. Start the agent.
prooflog agent --config ./demo/config.json &

# 5. Record events.
prooflog event deploy.completed \
  --config ./demo/config.json \
  --actor ci \
  --outcome success \
  --payload-json '{"version":"1.0.0","commit":"abc123"}'

prooflog event access.revoked \
  --config ./demo/config.json \
  --actor admin@acme \
  --outcome success \
  --payload-json '{"user":"bob"}'

# 6. Verify the evidence offline.
prooflog verify \
  --spool ./demo/spool \
  --checkpoints ./demo/verifier-data \
  --keys ./demo/verifier-keys.json

# 7. Generate the continuity report.
prooflog report \
  --spool ./demo/spool \
  --checkpoints ./demo/verifier-data \
  --keys ./demo/verifier-keys.json \
  --org acme \
  --period 2026-07-04:2026-07-04 \
  --out ./demo/report.md
```

---

## Common use cases

- Incident timeline evidence: prove what happened, in order, with cryptographic proof the log was not edited after the fact.
- Deployment and access-change records: prove which deployments and permission changes occurred and when, even if the change-management system is later modified.
- Backup and restore-test proof: record each backup job and restore test; the continuity report covers the full schedule.
- Secret rotation records: log key and credential rotation events for audit trails that survive key compromise.
- Client assurance pack: export a signed evidence bundle with a custody manifest for delivery to a client or auditor.
- Regulatory evidence support: produce a tamper-evidenced event timeline usable as technical evidence for CRA, NIS2, GDPR, and FADP obligations.
- Initial evidence audit: run `prooflog assess` over an organization's existing logs (IdP export, CloudTrail, immudb dump) to report — as an indicative Tier 0 assessment — what those logs can and cannot prove, before deploying any agent.

---

## FAQ

**Does Prooflog make us NIS2 / CRA / LPD / FINMA compliant?**
No. It helps produce technical evidence usable within those frameworks. The determination of whether a reporting obligation is triggered, the notification itself, and the legal interpretation of the evidence remain with you and your counsel.

**Would a Prooflog report hold up in court?**
It is defensible technical evidence, not presumptively admissible evidence. A self-signed hash chain has no legal presumption under eIDAS/ZertES; an expert witness would explain the cryptography, and the opposing party may challenge verifier independence. External anchoring to a qualified TSA (roadmap) is what upgrades checkpoints to the eIDAS Art. 41 presumption of time and integrity.

**Can the store operator read our events?**
Payloads: no. They are age-encrypted client-side and the store never holds decryption keys. Envelope metadata (source, sequence, event type, timing) is visible; that is why the wording is "client-side encrypted with minimal metadata disclosure", never "zero-knowledge".

**What if we self-host everything?**
Then one administrator controls agent, store, and verifier, and can rewrite history undetected. Reports generated from such a deployment state this limitation in the header. Meaningful assurance requires a verifier operated by an independent party.

**Why not just use immudb / a transparency log / Object Lock?**
Each solves a different layer: immudb is a verifiable database, transparency logs anchor public artifacts, Object Lock prevents object deletion. None of them proves collection continuity from the source host — that the stream of events between two points in time is complete, ordered, and was observed end-to-end. WORM proves nothing was deleted; a ledger database proves nothing was changed; Prooflog proves nothing is missing.

**Can we delete data to satisfy a GDPR/LPD erasure request?**
Records are never rewritten — that is the point of the tool. The metadata privacy model (pseudonymous actors with erasable per-subject salts, labels moved into the encrypted payload) ships in the current format: erasing a salt severs the link between a person and their events (`prooflog actor erase`) without breaking a single hash. Keep personal identifiers out of source IDs, which stay plaintext as infrastructure identity.

---

## Status

Prooflog is pre-alpha (v0.2.0-dev). Core packages are implemented and tested; the end-to-end demo runs. On-disk formats and gRPC APIs will change before v1.

v0.3 format break (Record v2): actors are now HMAC pseudonyms and free-text labels moved into the encrypted payload; the `labels` envelope field and the plaintext `actor` are gone. This is the sanctioned pre-alpha on-disk break: spools and segments written under Record v1 are no longer valid and must be regenerated.

Roadmap:

- RFC 3161 TSA anchoring: **shipped** (`prooflog verifier --tsa-url`); eIDAS-qualified TSA and Sigstore Rekor v2 remain on the roadmap, using the same `Anchor` interface
- Retention enforcement, legal holds, and forensic export: **shipped** (`prooflog store --retention-policy`, `prooflog hold`, `prooflog export`); per-framework deletion periods remain on the roadmap (frameworks are recorded and reported today, only `default_days` drives deletion)
- Log pipeline integrations: Vector sink, Fluent Bit output plugin, GitHub Actions step
- Additional report frameworks: GDPR Art. 33/34, DORA RTS, FINMA reporting cascade
- FIPS 140-3 mode: AES-256-GCM substitution via the pluggable `Sealer` interface (interface already defined)
- Independent hosted verifier option (for operators who want a third-party trust anchor without self-managing verifier infrastructure)

---

## Docs

- [`docs/architecture.md`](docs/architecture.md) — Component design, data flow, format contracts
- [`docs/threat-model.md`](docs/threat-model.md) — Full threat model: posture, detection conditions, self-host caveat, transport, holds, key compromise, scope limits
- [`docs/verifier-deployment-models.md`](docs/verifier-deployment-models.md) — Verifier trust tiers: single-admin to independent third party
- [`docs/standards.md`](docs/standards.md) — Requirements register with per-module traceability
- [`docs/event-taxonomy.md`](docs/event-taxonomy.md) — v1 event taxonomy and the Go client SDK
- [`docs/regulatory-context.md`](docs/regulatory-context.md) — Swiss ISA/NCSC, NIS2, CRA, GDPR/FADP evidence context
- [`docs/data_residency.md`](docs/data_residency.md) — Deployment matrix for data residency
- [`docs/comparisons/syslog-sign.md`](docs/comparisons/syslog-sign.md) — Prooflog vs RFC 5848 signed syslog
- [`docs/glossary.md`](docs/glossary.md) — Term definitions
- [`docs/legal_protection.md`](docs/legal_protection.md) — Legal protection considerations
- [`docs/assess/recipes.md`](docs/assess/recipes.md) — `prooflog assess`: Tier 0 assessment over existing logs (IdP, CloudTrail, immudb)
- [`docs/deployments/verify-from-s3.md`](docs/deployments/verify-from-s3.md) — Verifying prooflog evidence straight from S3 / Object Lock
- [`examples/continuity-report.md`](examples/continuity-report.md) — Sample continuity report output

---

## Contributing

Contributions are welcome. Before opening a pull request:

```bash
make test         # go test -race ./... — must pass
make audit        # golangci-lint + govulncheck — must be clean
make tidy         # go fmt + go mod tidy
```

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `test:`, …). Keep them atomic and focused.
- **Proto changes**: after editing `proto/prooflog/v1/`, run `make proto` to regenerate the stubs (requires `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`) and commit them together with the `.proto` change.
- **Tests define the contract.** Changing an existing test's assertions is a semantic change to the system — call it out explicitly in the PR description instead of adjusting tests until the code passes.
- **Design decisions** are recorded as numbered ADRs in [`docs/adr/`](docs/adr/). Anything that changes architecture, cryptography, or on-disk formats needs one. Requirements live in [`docs/standards.md`](docs/standards.md); code implementing a requirement carries a `REQ-*` comment linking back to it.
- Maintainers use [jj](https://github.com/jj-vcs/jj) colocated with git; plain git works fine for contributions.

---

## License

MIT. See [LICENSE](LICENSE).
