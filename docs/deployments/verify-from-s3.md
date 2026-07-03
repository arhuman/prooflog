# Verifying Prooflog evidence straight from S3 / Object Lock (Case A)

Prooflog verification is location-independent: the verifier recomputes every
hash and Merkle root from the exact stored bytes, so evidence archived to an S3
bucket — ideally with Object Lock — verifies at **full assurance** after a plain
fetch. No Prooflog service needs to be running, and no new code is involved:
this is the existing `prooflog verify` / `prooflog report` over restored files.

This is "Case A": prooflog-format evidence resting in foreign storage. It is
distinct from `prooflog assess`, which analyzes *foreign-format* logs at Tier 0
(see [assess/recipes.md](../assess/recipes.md)).

## What to archive

Continuously (cron, or a storage lifecycle sync) copy the sealed spool, the
verifier checkpoint data, the registered keys, and any anchor receipts:

```bash
aws s3 sync /var/lib/prooflog/spool          s3://acme-evidence/spool/ \
  --exclude "*.active"          # sealed spool files only; the active file is still being written
aws s3 sync /var/lib/prooflog/verifier-data  s3://acme-evidence/verifier-data/
aws s3 cp   /etc/prooflog/verifier-keys.json s3://acme-evidence/keys/verifier-keys.json
aws s3 sync /var/lib/prooflog/anchors        s3://acme-evidence/anchors/   # if TSA anchoring is on
```

`prooflog export` bundles (signed custody manifest) can be archived the same
way for point-in-time forensic snapshots.

## Bucket setup

- Versioning **on** (required by Object Lock).
- Object Lock in **compliance mode**, retention period matching your obligation
  (e.g. 1 year for PCI DSS 10.5.1; longer where required).
- Restrict credentials: Object Lock protects against deletion, not against an
  attacker who can rewrite the account's other state.

## To verify, later, on any machine

```bash
aws s3 sync s3://acme-evidence ./restored

prooflog verify \
  --spool ./restored/spool \
  --checkpoints ./restored/verifier-data \
  --anchors ./restored/anchors \
  --keys ./restored/keys/verifier-keys.json
# exit 0 = clean; exit 1 = findings

prooflog report \
  --spool ./restored/spool \
  --checkpoints ./restored/verifier-data \
  --anchors ./restored/anchors \
  --keys ./restored/keys/verifier-keys.json \
  --org acme --period 2026-01-01:2026-06-30 \
  --out continuity-report.md
```

## What this adds — and what it does not

Object Lock contributes tamper **resistance** and enforced retention for the
bytes at rest. The cryptographic guarantees (hash chain, signed checkpoints,
fork rejection) come from Prooflog and are unchanged by where the bytes live —
this is why any storage, even a plain directory, is safe under Prooflog's model.

The independence caveat is also unchanged: the checkpoints in `verifier-data`
are only as meaningful as the separation between the store operator and the
verifier operator. Locking the bucket does **not** create that separation — it
protects the archive of it. See
[verifier-deployment-models.md](../verifier-deployment-models.md).
