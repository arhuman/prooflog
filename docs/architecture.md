# Prooflog — Architecture

Design contract for the v1 system. Every load-bearing choice traces to a
requirement ID in `docs/standards.md` (REQ-C crypto, REQ-E evidence,
REQ-R regulatory). Product rationale lives in `objectif.md` and
`decisions.md`; this document is the implementation reference.

## 1. Goals and non-goals

**Goals:** tamper-evident recording of critical events; provable
continuity of observation; outage-tolerant collection; client-side
encrypted centralization; independent verification; regulator-ready
reports.

**Non-goals (Risk 1 in objectif.md):** search, dashboards, alerting,
correlation, exhaustive log collection. Prooflog is an evidence layer,
not a SIEM.

## 2. Components

Prooflog has exactly three interacting components. These names are
**normative** — the Go packages, CLI subcommands, and gRPC services
already use them, and all documentation must too:

- **Agent** — runs on the source host. Ingests events, assigns the
  monotonic sequence, builds the hash chain, encrypts payloads, writes
  the local spool, seals segments, and uploads them. (Full name at first
  mention: Proof Agent.)
- **Store** — the central service that persists the encrypted segments,
  acknowledges them only after durable write, deduplicates, and enforces
  retention. It is content-blind and never decrypts payloads. "Central"
  is a topology adjective, not part of the name; it is never a
  "collector" (the Agent is what collects) nor a "log store".
- **Verifier** — an independent service, run by a party separate from the
  Store operator. It **witnesses** each source's checkpoints — accepting
  them append-only and rejecting forks, using the transparency-log term
  for an independent checkpoint attester — then pulls segments to
  re-verify the hash chains and Merkle roots and emits the reports.
  Acting as witness is precisely what makes it the v1 trust anchor.

"Witness", "monitor", and "auditor" name what the Verifier *does* (it
witnesses checkpoints, monitors continuity, audits integrity); they are
roles, not additional components.

```
events (CLI / HTTP / stdin)
        │
        ▼
┌─────────────────┐   gRPC (mTLS)   ┌─────────────────┐
│ Agent            │ ───────────────▶│ Store            │
│ seq · chain ·    │  segments+ACK   │ blobs · index ·  │
│ spool · seal ·   │                 │ dedup · retention│
│ heartbeat        │                 └────────┬────────┘
└────────┬────────┘                           │ pull: records/segments
         │ checkpoints (signed notes)         ▼
         └──────────────────────────▶┌─────────────────┐
                                     │ Verifier         │
                                     │ consistency ·    │
                                     │ gaps · findings ·│
                                     │ reports          │
                                     └─────────────────┘
```

One static Go binary, subcommand per role:
`prooflog agent|store|verifier|event|heartbeat|verify|report|init|spool`.
The Verifier is operationally separate (hosted by an independent third
party) — separation of powers via independent checkpoint witnessing is
the v1 trust anchor (decisions.md).

**Trust model.** Tamper-evident per FAU_STG.2 "detect" (REQ-E-08):
rewriting history undetected requires compromising agent, store, AND
verifier. Fully self-hosted single-admin deployments lose this and must
say so in reports. The `Anchor` interface (REQ-C-15) strengthens this
externally without redesign.

### Anchor vs Verifier — two trust roles

The Verifier and the Anchor are distinct trust roles; do not conflate
them.

- **Verifier — active checking.** It witnesses checkpoints, refuses
  forks, recomputes roots, and detects gaps and drift. Its trust basis
  is **organizational independence**: the assurance holds only because a
  party separate from the store operator is doing the checking. When one
  administrator runs agent, store, and verifier, that basis collapses.
- **Anchor — passive external commitment.** It commits the exact bytes
  of a signed checkpoint to an external authority (an RFC 3161 TSA),
  proving **existence-at-time**. Its trust basis is **external
  attestation**, which works *without* verifier independence — an
  operator who controls all three components still cannot backdate a
  checkpoint the TSA already timestamped. This is precisely why REQ-C-15
  exists: to add a guarantee that does not rest on separation of powers.

The v1 wording "the verifier acts as the anchor" is retired. With WS5 the
roles are separate: the Verifier decides *consistency*, the Anchor
attests *time*. An anchor never checks a chain, and a verifier never
mints a timestamp. The RFC 3161 client is shipped; an eIDAS-qualified TSA
(Art. 41 legal presumption) and Rekor remain reserved under the same
interface.

### Retention, tombstones, and legal holds

Retention deletes ciphertext but never history. When a segment expires
under the policy (`store --retention-policy`, or the `--retention`
duration shorthand; only `default_days` drives deletion — per-framework
periods are recorded and reported, not yet enforced), the Store removes
the blob file and sets `deleted_at` on the segment row. The row survives
forever as a **tombstone**: its sequence range, Merkle root, and signed
checkpoint remain. The Verifier fetches tombstones (`ListTombstones`) and
reports the affected range as *expired-but-retained* — verifiable by the
retained signed checkpoint — instead of a false gap. A tombstone whose
root matches no accepted checkpoint raises `F-RETENTION`: a deletion that
cannot be tied to committed, signed history.

**Legal holds** override expiry. A hold (`prooflog hold place`) exempts a
source, or a sequence range within it, from deletion until released;
`EnforceRetention` skips any segment overlapping an active hold.

Retention and hold actions are themselves evidence. The Store seals
`system.retention_policy_changed`, `system.retention_deleted`,
`system.legal_hold_placed`, and `system.legal_hold_released` events into
the tamper-evident chain through a **designated agent's HTTP ingest**
(`store --agent-http`). When no agent is configured the action still
takes effect, but the event is not chain-sealed and the Store logs a
warning (graceful degradation).

## 3. Package map

| Package | Responsibility | Key REQs |
|---|---|---|
| `internal/envelope` | Record type, pinned byte serialization, hashing | C-04, C-13, E-07 |
| `internal/chain` | per-source hash chain link/verify | C-03 |
| `internal/merkle` | RFC 6962 tree, inclusion/consistency proofs | C-01, C-02 |
| `internal/note` | C2SP signed notes + tlog-checkpoints | C-06, C-07 |
| `internal/keys` | keygen, key files, key IDs, rotation metadata | C-11, C-12 |
| `internal/seal` | payload encryption via age | C-08, C-09 |
| `internal/spool` | append-only durable spool, offsets, pressure policy | E-03, E-04, E-09 |
| `internal/segment` | batch records → segment, checkpoint emission | C-01, C-07, C-14 |
| `internal/heartbeat` | heartbeat production incl. time-source metadata | E-06 |
| `internal/agent` | orchestration: ingest → seq → chain → spool → upload; local HTTP ingest | E-04 |
| `internal/store` | gRPC service, SQLite index + blob dir, dedup, ACK, retention | E-11, R-10 |
| `internal/verifier` | sync, checks, findings | C-02, C-07, E-05 |
| `internal/evidence` | common incident-evidence model | R-01 |
| `internal/report` | continuity report + framework projections (Markdown) | E-01, E-10, R-* |
| `internal/api` | generated protobuf + shared gRPC plumbing | — |
| `cmd/prooflog` | CLI wiring only, one file per subcommand | — |

**Dependency rule:** `envelope`, `chain`, `merkle`, `note`, `keys`,
`seal` are leaf packages (stdlib + x/crypto + filippo.io/age only, no
I/O beyond keys). `spool`, `segment`, `heartbeat` may depend on leaves.
Services (`agent`, `store`, `verifier`) may depend on everything below.
Nothing depends on services. `report` depends on `evidence` + verifier
findings types, never on transport.

## 4. Data model

### 4.1 Record

The unit of evidence. Serialized ONCE at acceptance to a single-line
JSON with fixed field order (Go struct order); those exact bytes are
what is hashed, stored, uploaded, and verified — never re-serialized
(REQ-C-04).

```json
{"v":2,"source_id":"vps-01/api","seq":1842,
 "event_type":"access.revoked","event_time":"2026-07-03T12:00:00.000000000Z",
 "ingest_time":"2026-07-03T12:00:00.104329000Z",
 "actor":"a1b2…<64 hex>","outcome":"success",
 "payload_ct":"<base64 age ciphertext>","payload_hash":"<hex sha256 of plaintext>",
 "key_id":"org-acme-2026-1","prev_hash":"<hex>"}
```

- Timestamps: pinned RFC 3339 UTC, 9-digit nanoseconds, uppercase T/Z
  (REQ-C-13).
- `actor` and `outcome` cover FAU_GEN.1 (REQ-E-07); empty when unknown.
  In v2 (BREAKING, pre-alpha) `actor` is a 64-hex HMAC pseudonym, never a
  plaintext identity; `outcome` is a closed enum
  (`success|failure|denied|unknown|""`). The free-text `labels` field was
  removed from the envelope entirely — see the payload wrapper below.
- Business payloads are age-encrypted per event (single-use file key per
  age spec — satisfies the one-key-one-message posture, REQ-C-08).
  System events (`system.*`, incl. heartbeats) carry `payload_clear`
  instead of `payload_ct` so the verifier can read them (objectif §8.4).

**Payload wrapper (labels).** Free-text labels are personal data and must not
sit in cleartext metadata, so they leave the envelope. When an event carries
labels the agent wraps the payload before encryption:

```json
{"labels":{"team":"x"},"data":<original payload or null>}
```

The wrapper exists **only** when labels are non-empty; with no labels the
original payload is encrypted unchanged (no wrapper). For business events the
wrapper is inside `payload_ct`; for `system.*` events it is folded into
`payload_clear`. Labels thus inherit payload confidentiality and erasability.

**Actor pseudonyms (privacy model).** Each actor identity maps to a stable
`HMAC-SHA256(salt_actor, actor)` pseudonym (`internal/pseudonym`). The
per-subject 256-bit salt is generated on first sight and stored only on the
source host (`salts.json`, 0600). Deleting a subject's salt crypto-shreds the
link between the person and their pseudonym in every past record without
rewriting a single record (GDPR Art. 17; HMAC not a bare hash, REQ-C-03).
Because the pseudonym is what gets hashed and chained, **the chain, Merkle
roots, and checkpoints stay fully verifiable without any salt** — verifiers
never see salts. `source_id` stays plaintext (infrastructure identity, not a
person; operators must keep personal identifiers out of it). The shred guarantee
covers the *live* store: once the salt is deleted no in-process path can
re-derive the pseudonym. It is best-effort against forensic disk recovery — the
salt file is rewritten by temp+rename, which does not scrub freed sectors, so
deployments needing erasure against physical-media recovery should host
`salts.json` on a full-disk-encrypted or secure-erase-capable volume.
- `record_hash = SHA-256(record_bytes)`; `prev_hash` = previous record's
  hash (genesis: 64 zero hex chars). The chain gives row-by-row offline
  verification; the Merkle tree (below) gives compact proofs.

### 4.2 Per-source Merkle log and checkpoints

Each source is an append-only RFC 6962 tree; leaf i = record with
seq i+1, leaf hash `SHA-256(0x00 ‖ record_bytes)` (REQ-C-01). At each
segment seal the agent emits a checkpoint — a C2SP tlog-checkpoint
signed as a C2SP signed note with its Ed25519 key (REQ-C-06/07):

```
prooflog/<org>/<source_id>
1842
<base64 tree root at size 1842>

— vps-01-api Az3grl…
```

Checkpoints go to the verifier directly (and to the store, which
forwards opportunistically). The verifier MUST verify consistency
between successive checkpoints of a source and refuse forks (REQ-C-02,
REQ-C-07) — this is the anti-truncation / anti-rewrite mechanism.

### 4.3 Segment

Upload/storage batch, sealed when 256 records accumulated or 60 s after
the first unsealed record, whichever first. Identified by UUIDv7
(REQ-C-14). A segment = the raw spool frames for `[seq_first, seq_last]`
plus its checkpoint. The signed checkpoint covers everything: any
mutation of stored bytes changes a leaf, hence the root.

### 4.4 Spool format

Per-source directory of segment files, `<seq_first>.plogseg`:

```
frame := uvarint(len(record_bytes)) ‖ record_bytes ‖ record_hash[32]
```

Binary framing preserves exact bytes (REQ-C-04); `prooflog spool cat`
pretty-prints for humans. Appends are fsynced before ACK to the event
producer (REQ-E-04 durable acceptance). Files are opened append-only;
sealed files are never reopened for writing. Disk pressure: configurable
`block` (default) or `drop-oldest-sealed-and-acked`, and crossing the
threshold emits `system.local_spool_pressure` (REQ-E-09).

### 4.5 Keys

`prooflog init` (REQ-C-11):
- per-agent Ed25519 signing keypair — private key stays on the host
  (`agent.key`, 0600);
- per-org age X25519 identity — private key output ONCE for offline
  backup, never uploaded; public recipient key distributed to agents.

Key IDs per C2SP signed-note (4-byte truncated SHA-256).

Rotation is a signed handoff. The agent generates a new signing key under a new
distinct name, emits a `system.key_rotated` event naming both key IDs as the next
leaf, then seals the current tree under the OLD key — so the outgoing key
cryptographically attests the change. It swaps the batcher's signer and persists
the new key; every later checkpoint is signed by the new key. Because the Merkle
tree continues unbroken and both public keys stay registered with the verifier,
each checkpoint verifies against whichever key signed it and the rotated chain
verifies CLEAN (no findings). Old public keys are retained forever for
verification (REQ-C-12).

Revocation records a trust boundary. A `system.key_revoked` event captures the
revoked key ID, reason, and suspected-exposure start; it does not itself generate
a new key (operators rotate separately). Any report covering the period surfaces
it as an explicit `F-KEYREV` finding stating that events signed by the key inside
the exposure window are suspect.

## 5. Interfaces (evolution points)

```go
// anchor: passive external commitment, distinct from the verifier (REQ-C-15).
// Shipped: RFC 3161 TSA. Reserved: eIDAS-qualified TSA, Rekor.
type Anchor interface {
    Anchor(ctx context.Context, signedNote []byte) (Receipt, error)
    Name() string
}

// seal: v1 = age; interface kept AEAD-agnostic for a FIPS mode (REQ-C-10).
type Sealer interface {
    Seal(plaintext []byte, recipients []Recipient) ([]byte, error)
    Open(ciphertext []byte, identity Identity) ([]byte, error)
}

// spool consumer side (uploader), replay from ACKed offset.
type Spool interface {
    Append(rec envelope.Record) error
    Iter(fromSeq uint64) (RecordIter, error)
    LastSeq() uint64
    MarkAcked(uptoSeq uint64) error
}

// store persistence, SQLite+fs in v1, S3 later.
type SegmentStore interface {
    Put(ctx context.Context, seg segment.Sealed) error
    Has(ctx context.Context, id segment.ID) (bool, error)
    Get(ctx context.Context, id segment.ID) (segment.Sealed, error)
}

// report renderers: markdown v1; framework projections implement this.
type Renderer interface {
    Render(m evidence.ReportModel) ([]byte, error)
}
```

## 6. Protocols

- **Ingest (local only):** CLI / `POST /v1/events` on 127.0.0.1 /
  stdin pipe. The agent assigns `seq` and `ingest_time`, serializes,
  chains, appends; HTTP 200 only after fsync.
- **Agent → Store:** gRPC over mTLS (REQ-E-04 secure transport):
  `UploadSegment(stream Frame) returns (SegmentAck)` — ACK only after
  durable persistence; dedup by (source_id, seq range, root).
  Retry with exponential backoff; replay resumes from last ACK;
  outages bracketed by `system.network_outage` / `system.replay_completed`.
- **Agent → Verifier:** `SubmitCheckpoint(SignedNote)` — small, frequent,
  survives store compromise.
- **Verifier → Store:** `PullSegments(source, from_seq)` — the verifier
  fetches raw frames (ciphertext included; it stays content-blind but
  byte-complete, so it can recompute every hash).

## 7. Verification algorithm (per source, per period)

1. Signatures: every checkpoint note verifies against a registered key.
2. Consistency: checkpoints form one append-only tree history (REQ-C-02).
3. Recompute: leaf hashes from pulled frames reproduce checkpoint roots.
4. Chain: `prev_hash` linkage intact; `seq` strictly monotonic, no gaps.
5. Continuity: heartbeat cadence vs policy → observation gaps, bounded
   by `agent_stopped/started` when present (REQ-E-06).
6. Transport: outage events vs ACK history → buffered/replayed/lost.
7. Cross-check: store contents vs agent checkpoints → divergence.
8. Findings → `evidence.ReportModel` → renderer.

Offline mode (`prooflog verify --bundle`): same steps from an exported
bundle, no network (REQ-E-10 repeatability).

## 8. Reports

`internal/evidence` holds the superset incident model (REQ-R-01):
discovery time, type, C-I-A impact, severity, IoCs, measures, root
cause, contacts — each field tagged `auto` (populated from verified
events) or `manual` (operator input slot). Framework projections
(REQ-R-02…09) select and format fields per regime; deadline clocks
computed from the evidenced discovery event (REQ-R-11).

v1 renderers: **continuity/integrity report** (target output:
`examples/continuity-report.md`) and **NCSC 24h/14d pair** (REQ-R-02).
Others post-v1.

## 9. Traceability

Requirements → modules table lives in `docs/standards.md`. CI should
fail if a REQ ID referenced here disappears from the register.
