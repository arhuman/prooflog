# `prooflog assess` — extraction recipes

`prooflog assess` runs Prooflog's continuity analyzers over an organization's
**existing** logs and produces a Tier 0 "Evidence Assessment Report":
analytical findings that are *indicative, never cryptographically attested*
(see [ADR-0008](adr/0008-assurance-tiers-and-assess-mode.md)). It is the
initial-audit tool — it shows, on the organization's own data, what it cannot
today prove, and the remediation is to capture with a Prooflog agent (Tier 1+).

Assess never talks to a storage system. You export to JSONL yourself, then feed
it in with a mapping profile. This keeps Prooflog storage-agnostic and adds no
per-vendor drivers. For dual control, have two people run and archive the
export; the assessment's input digest binds the report to exactly those bytes.

```bash
prooflog assess \
  --input export.jsonl[.gz] [--input more.jsonl]... \
  --profile <name|path.json> \
  --period 2026-01-01:2026-06-30 \
  --heartbeat-interval 5m --max-silence 15m \
  --org acme --out assessment.md [--json findings.json]
```

Exit code is non-zero when any indicative finding is raised (like `verify`), so
it drops into CI and engagement scripts. Bundled profiles: `generic`,
`idp-signin`, `cloudtrail`, `immudb-export`. Custom profiles are a JSON file
passed by path; the schema is in
[ADR-0008](adr/0008-assurance-tiers-and-assess-mode.md) and the bundled
profiles under `internal/assess/profiles/`.

## Identity provider sign-in / audit logs

The flagship case: managed IdPs retain sign-in logs for only weeks (see
[legal_protection.md](legal_protection.md)). Pull within the retention window
and assess. Export via the provider's audit API (paginated); write one JSON
object per line. The `idp-signin` profile maps a Graph-style shape and declares
**no sequence and no heartbeat** — so the report states plainly that gap and
observation-gap analysis were *impossible on this export*, which is the point.

```bash
# your paginator writes signins.jsonl (one record per line)
prooflog assess --input signins.jsonl --profile idp-signin \
  --org acme --period 2026-01-01:2026-06-30 --out idp-assessment.md
```

## AWS CloudTrail (from S3)

CloudTrail files are gzipped JSON with a `{"Records":[...]}` envelope. Unwrap to
one record per line with `jq`, then assess. No sequence, so gap analysis is
impossible; coverage and timestamp analysis apply.

```bash
aws s3 sync s3://acme-cloudtrail/AWSLogs/ ./ct
for f in $(find ./ct -name '*.json.gz'); do zcat "$f"; done \
  | jq -c '.Records[]' > cloudtrail.jsonl
prooflog assess --input cloudtrail.jsonl --profile cloudtrail \
  --org acme --period 2026-01-01:2026-06-30 --out cloudtrail-assessment.md
```

## immudb

Export the relevant table/keys to JSONL, one row per line, with the transaction
id as `tx`. The `immudb-export` profile treats `tx` as the sequence — but note
it is monotonic **per database**, not per business source, so sequence gaps
reflect the whole store's transaction stream. State that caveat in any report
you hand over.

```bash
# example: your immuclient/SDK dump script writes immudb.jsonl lines like
#   {"tx":1024,"ts":1767225600,"source":"payments","type":"charge","actor":"svc"}
prooflog assess --input immudb.jsonl --profile immudb-export \
  --org acme --period 2026-01-01:2026-06-30 --out immudb-assessment.md
```

## Generic JSONL (any SIEM/DB export)

Reduce any export to `{ "source", "time" (RFC3339), "seq", "type", "actor" }`
per line and use `--profile generic`, or write a small custom profile mapping
your field names. `type == "heartbeat"` marks a heartbeat under the generic
profile, enabling observation-gap analysis when your data carries liveness pings.

## Large exports

Reads are capped by default at 4 GiB of input (`--max-bytes`) and 10,000,000
records (`--max-records`): the export is foreign data, and a default run must
not be exhaustible by an oversized dump or a decompression bomb. Pass
`--max-bytes 0` or `--max-records 0` to lift a cap explicitly.

When a cap stops the read, the report carries an unmissable "INPUT TRUNCATED —
THIS ASSESSMENT IS PARTIAL" banner and a warning goes to stderr: findings cover
only the input read before the cap, so absence of a finding says nothing about
the rest. Re-run uncapped, or narrow the export (shorter period, one source per
file) so it fits under the caps.

## The honest boundary

Assess attests nothing. It reports anomalies *in the export as presented*; an
unsigned export can be internally consistent and still be incomplete or altered
upstream. Only Tier 1+ capture makes completeness and integrity provable. Every
assessment report says so, and reserves the verification certificate for
captured evidence.
