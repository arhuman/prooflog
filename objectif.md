# Prooflog — Encrypted, verifiable, outage-tolerant cyber evidence log

## 1. Objective

Prooflog is a **technical evidence**-oriented logging system for organizations that need to demonstrate rapidly and verifiably:

* what happened;
* when it happened;
* which source produced it;
* whether events were tampered with;
* whether observability gaps exist;
* whether collection continued despite network outages;
* whether logs can be used without exposing private data to the central operator.

The goal is not to replace existing log platforms, SIEMs, or observability stacks. The goal is to provide a complementary layer of **proof, continuity, and integrity**.

Short version:

> Prooflog turns critical events into verifiable evidence.

Long version:

> Prooflog is a client-side encrypted, tamper-evident, outage-tolerant cyber evidence register with a central Store and an independent Verifier.

## 2. Problem

Organizations often have logs, but those logs do not always answer the questions that matter most during an incident, an audit, or a client inquiry:

* Can it be proven that logs have not been modified?
* Can the deletion of an event already accepted by the local system be detected?
* Can an unobserved window be detected?
* Can it be proven that a network outage did not cause log loss?
* Can an incident timeline be reconstructed within 24 or 72 hours?
* Can evidence be centralized without the provider seeing sensitive data?
* Can a readable report be provided for an authority, an auditor, or a client?

Traditional log platforms are excellent for collecting, searching, alerting, and visualizing. They are less often designed as cryptographic proof systems with verifiable continuity and strong confidentiality.

## 3. Positioning

Prooflog does not position itself as:

* a full SIEM;
* a competitor to Splunk, Elastic, Datadog, Loki, Wazuh, or Graylog;
* a general-purpose observability tool;
* a log search engine;
* a full GRC platform;
* a legal compliance guarantee.

Prooflog positions itself as:

> A technical evidence layer on top of or alongside existing log systems.

Cautious commitment:

> Prooflog helps produce actionable technical evidence for incidents, audits, compliance, and client inquiries.

Commitment to avoid:

> Prooflog makes your organization compliant with NIS2, CRA, LPD, or FINMA.

## 4. Legal and Regulatory Context

### 4.1 Switzerland — NCSC reporting

Since 1 April 2025, Swiss operators of critical infrastructure must report certain cyberattacks to the National Cyber Security Centre within 24 hours of discovery. A supplementary report must then be provided within 14 days.

Prooflog can help produce quickly:

* an incident timeline;
* the affected systems;
* the actions taken;
* unobserved windows;
* the log integrity status;
* evidence of collection continuity or interruption.

### 4.2 Switzerland — LPD / OPDo

The Federal Act on Data Protection protects the rights of individuals whose personal data is processed. The Federal Data Protection and Information Commissioner provides guidance on data breach notifications, in particular when the risk to the individuals concerned is likely to be high.

Prooflog can help document:

* accesses to personal data;
* sensitive exports or processing operations;
* permission changes;
* incident events;
* corrective measures;
* evidence of non-tampering with audit trails.

### 4.3 European Union — NIS2

ENISA published in 2025 technical guidance for NIS2 implementation, with practical recommendations, evidence examples, and mappings between regulatory requirements and security measures.

Prooflog can contribute to requirements related to:

* incident management;
* monitoring and detection;
* change control;
* continuity;
* auditability;
* access management;
* supply chain security;
* evidence retention.

### 4.4 European Union — Cyber Resilience Act

The Cyber Resilience Act requires manufacturers of products with digital elements to notify certain actively exploited vulnerabilities and severe incidents. The reporting rules specify in particular an initial alert within 24 hours, a full notification within 72 hours, and a final report as applicable.

Prooflog can help software publishers reconstruct:

* which version was in production;
* which commit or artifact was deployed;
* which vulnerability was detected;
* when the fix was applied;
* who triggered the action;
* what evidence accompanies the release;
* whether critical events are complete and intact.

## 5. Product Hypothesis

Legal constraints do not always explicitly require "immutable zero-knowledge logs with local fallback".

But they create a cluster of obligations around:

* evidence;
* traceability;
* rapid notification;
* integrity;
* confidentiality;
* continuity;
* audit capability;
* post-incident reconstruction capability.

*(Market hypothesis and target segments: maintained in internal strategy notes, not versioned.)*

## 6. Key Features

### 6.1 Tamper-evident / immutable

Each event accepted locally is integrated into a cryptographic chain:

* `source_id`;
* monotonic sequence number;
* payload hash;
* hash of the previous event;
* hash of the current event;
* per-segment signature.

Purpose:

* detect deletion;
* detect modification;
* detect reordering;
* detect naive retroactive insertion;
* prove the integrity of a period.

Careful wording:

> The system is tamper-evident rather than absolutely unforgeable.

### 6.2 Local fallback

The local agent must continue writing events even when the network or the Store is unavailable.

Features:

* local append-only spool;
* durable write to disk;
* retry;
* per-segment Store ACK;
* resume from confirmed offset;
* server-side deduplication;
* backpressure;
* disk thresholds;
* reporting of offline windows;
* automatic replay.

Purpose:

> A network outage must not create silent evidence loss.

### 6.3 Continuity heartbeat

The heartbeat becomes a core primitive.

It serves to prove that the source was alive, observable, and capable of logging.

Heartbeat event example:

```json
{
  "type": "system.heartbeat",
  "source_id": "vps-01/api",
  "seq": 1843,
  "event_time": "2026-07-03T10:02:00Z",
  "agent": {
    "version": "0.1.0",
    "uptime_seconds": 86400
  },
  "continuity": {
    "last_local_seq": 1842,
    "last_uploaded_seq": 1839,
    "last_ack_seq": 1839,
    "queue_depth": 4
  },
  "health": {
    "disk_free_bytes": 39120404480,
    "clock_drift_ms": 42
  },
  "prev_hash": "...",
  "event_hash": "..."
}
```

The heartbeat allows detection of:

* abnormal silence;
* an unobserved window;
* a stopped agent;
* a network outage;
* an upload delay;
* queue buildup in the local queue;
* clock drift;
* complete or incomplete recovery.

Important:

> A timestamp alone does not prove the loss of an event. The heartbeat allows proving an observability gap.

### 6.4 Monotonic sequence

Each source assigns a local sequence number before transmission.

Example:

```json
{
  "source_id": "vps-01/api",
  "seq": 1842,
  "event_type": "access.revoked",
  "prev_hash": "...",
  "event_hash": "..."
}
```

If the server receives:

```text
1840
1841
1843
```

then event `1842` is missing.

Important limitation:

> Event loss can only be detected if the event was accepted by the local agent or reserved by an intent protocol. If the application never emits it, the system cannot invent it.

### 6.5 Intent/result protocol for critical actions

For sensitive operations, Prooflog can provide a two-phase protocol:

```text
intent → result
```

Examples:

```text
seq 2001: intent access.revoke alice github
seq 2002: result access.revoke alice github success
```

Use cases:

* access revocation;
* admin role change;
* secret rotation;
* data export;
* account deletion;
* deployment;
* restore test;
* configuration change;
* incident notification.

This allows detecting:

* action started without a result;
* critical action not completed;
* action requiring supplementary evidence.

### 6.6 Zero-knowledge / client-side encryption

Business payloads are encrypted client-side before centralization.

The Store keeps only:

* encrypted payload;
* minimal metadata;
* hash;
* source;
* sequence;
* timestamps;
* signature;
* segment;
* information required for verification.

Careful wording:

> Prooflog targets a client-side encrypted model with minimal metadata disclosure.

To avoid:

> Absolute zero-knowledge.

Because some metadata remains visible:

* event frequency;
* payload size;
* source;
* event type;
* timestamps;
* activity periods;
* silence periods.

### 6.7 Centralization

The Store persists encrypted segments and confirms their persistence.

Responsibilities:

* receive segments;
* persist;
* ACK;
* deduplicate;
* manage retention;
* expose reception status;
* provide the blobs required for an audit or evidence restoration.

It does not necessarily need to be able to decrypt payloads.

### 6.8 Independent Verifier

The Verifier is separate from the Store.

It receives or verifies:

* Merkle roots;
* signatures;
* sequences;
* checkpoints;
* heartbeats;
* ACK status;
* roots per period;
* anchoring evidence.

It can produce reports without accessing private content.

Role:

* verify chains;
* detect sequence gaps;
* detect temporal gaps;
* verify signatures;
* detect divergences between local, Store, and checkpoints;
* generate integrity and continuity reports.

Value:

> Separation of duties between storage and verification.

### 6.9 Evidence reports

Example report:

```text
Prooflog Continuity Report

Source: vps-01/api
Period: 2026-07-01 → 2026-07-03

Heartbeat:
- Expected interval: 60s
- Expected count: 4320
- Observed count: 4318
- Longest observation gap: 2m04s
- Max allowed silence: 3m
- Status: OK

Transport:
- Network outages: 2
- Longest outage: 8m32s
- Buffered events during outages: 441
- Replay completed: yes

Integrity:
- Sequence gaps: none
- Hash chain: valid
- Segment signatures: valid
- External seals: valid

Privacy:
- Payloads encrypted client-side: yes
- Store can decrypt payloads: no

Conclusion:
The source remained observable during the period.
Temporary connectivity loss occurred, but no accepted events were lost.
```

Possible reports:

* NCSC 24h report;
* 14-day post-incident report;
* NIS2 evidence report;
* CRA vulnerability/incident timeline report;
* LPD/OPDo data breach reconstruction report;
* log continuity report;
* cryptographic integrity report;
* access review report;
* restore test report;
* deployment/release evidence report.

## 7. Architecture

### 7.1 Overview

```text
┌────────────────────┐
│ App / Host / CI     │
└─────────┬──────────┘
          │ events
          ▼
┌────────────────────────────┐
│ Local Proof Agent           │
│ - receives events           │
│ - emits heartbeat           │
│ - local append-only spool   │
│ - sequence numbers          │
│ - hash chain                │
│ - encrypts payloads         │
│ - signs segments            │
│ - retries upload            │
└─────────┬──────────────────┘
          │ encrypted segments + metadata
          ▼
┌────────────────────────────┐
│ Store                       │
│ - stores encrypted payloads │
│ - ACKs persisted segments   │
│ - deduplicates              │
│ - retention                 │
└─────────┬──────────────────┘
          │ roots / seq / heartbeat status
          ▼
┌────────────────────────────┐
│ Verifier                    │
│ - verifies chains           │
│ - detects seq gaps          │
│ - detects heartbeat gaps    │
│ - timestamps roots          │
│ - emits audit reports       │
└────────────────────────────┘
```

### 7.2 Components

#### Local Proof Agent

Responsibilities:

* receive events;
* assign the monotonic sequence;
* emit heartbeats;
* encrypt payloads;
* write locally with durability;
* build the hash chain;
* sign segments;
* upload to the Store;
* manage retry;
* expose local status.

#### Store

Responsibilities:

* receive segments;
* persist encrypted blobs;
* ACK only after persistence;
* manage deduplication;
* manage retention;
* provide ingestion status;
* transmit or expose roots to the verifier.

#### Verifier

Responsibilities:

* verify signatures;
* verify hash chains;
* verify sequence;
* verify heartbeat continuity;
* detect divergences;
* generate reports;
* periodically anchor roots.

#### Client / CLI

Responsibilities:

* send manual events;
* trigger reports;
* verify offline;
* export evidence;
* integrate CI/CD.

Examples:

```bash
prooflog event deploy.completed --service api --version v1.2.3
prooflog heartbeat
prooflog verify --period 2026-07-01:2026-07-03
prooflog report --framework ncsc
```

## 8. API and Protocols

### 8.1 HTTP/JSON for adoption

Universal interface for webhooks, scripts, and existing tools.

```http
POST /v1/events
Content-Type: application/json
```

```json
{
  "source_id": "vps-01/api",
  "event_type": "deploy.completed",
  "event_time": "2026-07-03T12:00:00Z",
  "labels": {
    "service": "api",
    "env": "prod"
  },
  "payload": {
    "version": "v1.2.3",
    "commit": "abc123"
  }
}
```

### 8.2 gRPC for controlled agents

gRPC is recommended for agent-to-server flows:

* streaming;
* ACK;
* backpressure;
* compression;
* mTLS;
* checkpoints;
* high performance.

But gRPC must not be the only public interface.

Recommended design:

```text
Various sources
  → HTTP/JSON / CLI / syslog / file tail / webhooks
  → local agent
  → reliable gRPC streaming
  → encrypted Store
  → verifier
```

### 8.3 Stable envelope + flexible payload

Recommended design:

* typed stable envelope;
* flexible encrypted business payload;
* typed and visible heartbeats, seals, and checkpoints.

Conceptual example:

```protobuf
message EventEnvelope {
  string source_id = 1;
  uint64 seq = 2;
  string event_type = 3;
  int64 event_time_unix_nano = 4;
  int64 ingest_time_unix_nano = 5;

  map<string, string> labels = 6;

  bytes encrypted_payload = 7;
  bytes payload_hash = 8;
  bytes prev_hash = 9;
  bytes event_hash = 10;

  bytes segment_id = 11;
  bytes signature = 12;

  string key_id = 13;
  string cipher_suite = 14;
}
```

### 8.4 Visible heartbeat

The heartbeat must remain visible enough for the Verifier to work without decrypting business logs.

```protobuf
message Heartbeat {
  string source_id = 1;
  uint64 seq = 2;
  int64 event_time_unix_nano = 3;

  uint64 last_local_seq = 4;
  uint64 last_uploaded_seq = 5;
  uint64 last_ack_seq = 6;
  uint64 queue_depth = 7;

  int64 clock_drift_ms = 8;
  uint64 uptime_seconds = 9;

  bytes prev_hash = 10;
  bytes event_hash = 11;
  bytes signature = 12;
}
```

## 9. Interoperability with existing log platforms

Prooflog must be interoperable by design.

### 9.1 Possible inputs

* HTTP webhooks;
* CLI;
* stdin;
* Unix socket;
* syslog;
* file tailing;
* journald;
* Docker events;
* Kubernetes events;
* GitHub Actions;
* GitLab CI;
* OpenTelemetry logs;
* Fluent Bit output plugin;
* Vector sink/source;
* Wazuh/Elastic/Splunk forwarder bridge.

### 9.2 Possible outputs

Prooflog must be able to export to:

* ElasticSearch / OpenSearch;
* Grafana Loki;
* Splunk HEC;
* Datadog logs intake;
* Graylog GELF;
* Wazuh archives;
* S3 / MinIO;
* local files;
* SIEM via syslog;
* OpenTelemetry Collector.

### 9.3 Positioning relative to existing platforms

Prooflog does not replace:

* full-text search;
* dashboards;
* advanced alerting;
* SIEM correlation rules;
* APM;
* metrics;
* traces;
* behavioral detection.

Prooflog adds:

* integrity evidence;
* continuity evidence;
* client-side encryption;
* verifiable local fallback;
* independent Verifier;
* audit reports;
* regulatory evidence packs.

### 9.4 Sidecar / overlay mode

Possible integration modes:

#### Primary agent mode

The application sends directly to Prooflog.

#### Sidecar mode

Prooflog receives a copy of critical events alongside the existing stack.

#### Bridge mode

Prooflog reads from Vector, Fluent Bit, Loki, Elastic, or local files, then seals only critical events.

#### Evidence-only mode

Prooflog does not collect all logs. It collects only:

* deployments;
* access changes;
* heartbeats;
* restore tests;
* incidents;
* notifications;
* configuration changes;
* data exports;
* secret rotations.

This mode is probably the best MVP.

## 10. Critical events to support first

### System

* `system.heartbeat`
* `system.agent_started`
* `system.agent_stopped`
* `system.clock_drift_detected`
* `system.local_spool_pressure`
* `system.network_outage`
* `system.replay_completed`

### Access

* `access.granted`
* `access.revoked`
* `access.role_changed`
* `access.admin_created`
* `access.admin_removed`
* `access.review_completed`

### Deployment

* `deploy.started`
* `deploy.completed`
* `deploy.failed`
* `release.sbom_generated`
* `release.vulnerability_scan_completed`
* `release.artifact_signed`

### Backup / restore

* `backup.completed`
* `backup.failed`
* `restore_test.started`
* `restore_test.completed`
* `restore_test.failed`

### Incident

* `incident.detected`
* `incident.triaged`
* `incident.contained`
* `incident.notified`
* `incident.resolved`
* `incident.report_completed`

### Sensitive data

* `data.exported`
* `data.deleted`
* `data.anonymized`
* `data.accessed`
* `data.breach_suspected`
* `data.breach_confirmed`

## 11. Recommended MVP

### MVP 0 — fake report

Before writing code, produce 2-3 report examples:

* NCSC 24h report;
* NIS2 evidence report;
* CRA incident timeline report;
* log continuity report.

Goal: test whether the report format answers the questions auditors, authorities, and operators actually ask.

### MVP 1 — local register

* CLI;
* local agent;
* append-only spool;
* monotonic sequence;
* hash chain;
* heartbeat;
* local Markdown report;
* local verification.

No complex centralization yet.

### MVP 2 — encrypted centralization

* upload encrypted segments;
* ACK;
* retry;
* replay;
* central storage;
* transport report.

### MVP 3 — independent Verifier

* roots reception;
* gap detection;
* integrity report;
* continuity report;
* optional external anchoring.

### MVP 4 — ecosystem integrations

* Vector;
* Fluent Bit;
* OpenTelemetry;
* GitHub Actions;
* Docker;
* S3/MinIO.

## 12. Open questions

### 12.1 Legal

* What exact logging obligations exist in Swiss law applicable to federal bodies, public institutions, higher-education and research institutions, and sensitive data processing?
* To what extent can a tamper-evident register be recognized as acceptable evidence?
* What retention periods are required by sector?
* How to reconcile immutable logs with the right to erasure and data minimization?
* Which metadata can be retained without violating confidentiality?
* What public wording avoids promising legal compliance?
* What differences exist between Switzerland, the EU, France, Germany, and the FINMA, healthcare, and research sectors?

### 12.2 Technical

* What exact cryptographic model?
* Simple hash chain or Merkle tree per segment?
* Ed25519 signature per event, per segment, or per root?
* What key rotation scheme?
* How to handle agent key compromise?
* How to handle clock drift?
* How to handle out-of-order events?
* What heartbeat granularity?
* How to prevent heartbeats from becoming too costly?
* How to prove that a local segment was not rewritten before sealing?
* What minimal offline-first support?
* What backpressure strategy?
* What external anchoring strategy: S3 Object Lock, signed Git, transparency log, timestamping service?
* What canonical format for signing JSON/protobuf events?

### 12.3 Product

*(Product/commercial questions: maintained in internal strategy notes, not versioned.)*

### 12.4 Competition

*(Competitive analysis: maintained in internal strategy notes, not versioned.)*

## 13. Risks

### Risk 1 — building a SIEM

To avoid at all costs.

Prooflog must not become:

* a search engine;
* a dashboard;
* a correlator;
* an alerting engine;
* an observability suite;
* an Elastic/Splunk replacement.

### Risk 2 — overstated legal promise

Do not say:

> Compliant with NIS2 / CRA / LPD / FINMA.

Say:

> Helps produce actionable technical evidence within these frameworks.

### Risk 3 — poorly worded zero-knowledge

The payload can be encrypted, but metadata remains visible.

Say:

> Client-side encrypted payloads with minimal metadata disclosure.

### Risk 4 — crypto complexity

Avoid the "private blockchain for a text file" syndrome.

The system must remain:

* readable;
* auditable;
* verifiable offline;
* simple to explain;
* simple to deploy.

### Risk 5 — market too abstract

*(Market risk analysis: maintained in internal strategy notes, not versioned.)*

## 14. Messaging

*(Maintained in internal strategy notes, not versioned.)*

## 15. Product summary

The direction is promising if Prooflog stays focused on:

```text
evidence > logs
continuity > storage
verification > dashboard
critical events > exhaustive collection
interoperability > replacement
actionable reports > crypto technology
```

The most promising product is not:

> an immutable log system.

But:

> a technical evidence register that detects observability gaps, verifies the integrity of critical events, encrypts data client-side, tolerates network outages, and produces actionable reports for incidents, audits, and regulatory requirements.
