# v1 Event Taxonomy

This is a **starting set** for common security-relevant events, not an
exhaustive standard. Prooflog records whatever event types you send; this
taxonomy is a curated baseline so teams can start recording consistent,
verifiable evidence without inventing conventions from scratch. Extend it with
your own dotted types as your needs grow.

## What event types are for

An event type names *what happened*, in a stable, machine-readable form. It is
the primary axis a verifier or auditor filters and reasons over. Because it is
stable and plaintext (see [Privacy rules](#privacy-rules)), keep it generic and
free of any subject-specific detail.

**Naming convention:** `domain.action`, all lowercase, dotted. The domain is a
noun (`deploy`, `access`, `secret`), the action a verb or state
(`started`, `revoked`, `rotated`). The `system.*` namespace is **reserved for
the prooflog agent** — applications must never emit it.

**How to send events** (all three hit the same ingest contract, REQ-E-04):

- Go: the [`client`](../client) package — `client.New(...)` + `Send`.
- CLI: `prooflog event <type> [flags]`.
- HTTP: `POST /v1/events` to the local agent.

Each event-type constant below matches a constant in the `client` package
(single source of truth) — e.g. `deploy.started` is `client.EventDeployStarted`.

## Domains

### deploy

| Event type | When | Recommended payload fields | Criticality |
|------------|------|----------------------------|-------------|
| `deploy.started` | A deployment or release begins | `service`, `version`, `environment` | low |
| `deploy.completed` | A deployment finishes successfully | `service`, `version`, `environment`, `duration_s` | medium |
| `deploy.failed` | A deployment fails or is rolled back | `service`, `version`, `environment`, `reason` | high |

### access

| Event type | When | Recommended payload fields | Criticality |
|------------|------|----------------------------|-------------|
| `access.granted` | A subject is granted access to a resource | `resource`, `role`, `granted_to` | medium |
| `access.revoked` | A subject's access is removed | `resource`, `revoked_from`, `reason` | high |
| `access.privilege_changed` | A subject's privilege level changes | `resource`, `from_role`, `to_role` | high |

### secret

| Event type | When | Recommended payload fields | Criticality |
|------------|------|----------------------------|-------------|
| `secret.rotated` | A credential or key is rotated | `secret_id`, `kind` | medium |
| `secret.exposed` | A secret is found leaked or exposed | `secret_id`, `channel`, `scope` | high |
| `secret.revoked` | A secret is invalidated | `secret_id`, `reason` | high |

### backup

| Event type | When | Recommended payload fields | Criticality |
|------------|------|----------------------------|-------------|
| `backup.completed` | A backup finishes successfully | `target`, `size_bytes`, `retention` | medium |
| `backup.restore_tested` | A restore drill is performed | `target`, `verified`, `duration_s` | medium |
| `backup.failed` | A backup or restore fails | `target`, `reason` | high |

### incident

| Event type | When | Recommended payload fields | Criticality |
|------------|------|----------------------------|-------------|
| `incident.detected` | An incident is first detected | `incident_id`, `severity`, `source` | high |
| `incident.triaged` | An incident is assessed and categorized | `incident_id`, `severity`, `category` | medium |
| `incident.reported` | An incident is reported to authorities or stakeholders | `incident_id`, `reported_to` | high |
| `incident.resolved` | An incident is closed | `incident_id`, `resolution` | medium |

### data

| Event type | When | Recommended payload fields | Criticality |
|------------|------|----------------------------|-------------|
| `data.exported` | Data is exported out of a system | `dataset`, `format`, `destination` | high |
| `data.deleted` | Data is deleted (e.g. an erasure request) | `dataset`, `reason` | high |
| `data.retention_hold_placed` | A retention or legal hold is placed on data | `dataset`, `hold_id`, `reason` | high |

## Privacy rules

In the stored envelope, `event_type` and `source_id` stay **plaintext** — they
are never encrypted. `actor` is transformed into an **erasable HMAC pseudonym**,
and `labels` and `payload` are folded into the **client-side-encrypted**
payload. Therefore:

- **Never** put personal data, secrets, tokens, emails, or
  hostnames-that-identify-a-person into `event_type` or `source_id`.
- Put the subject identity in `actor` (stored as a pseudonym you can later
  erase per GDPR Art. 17).
- Put all detail — who, what, which record — in the encrypted `payload` or
  `labels`.

**Good:** type `access.revoked`, actor `admin@acme`, payload `{"user":"bob"}`.

**Bad:** type `access.revoked.bob@example.com` — this leaks a person's email
into the plaintext, unerasable envelope.

See [`docs/threat-model.md`](threat-model.md) for the full privacy posture.

## `system.*` reference

These types are **emitted by prooflog, not by your application**. They are
listed here only so readers recognize them in a verified log; the agent rejects
any attempt by an application to send them.

| Event type | Emitted when |
|------------|--------------|
| `system.heartbeat` | The agent proves a source was live at a timestamp |
| `system.agent_started` | The agent process starts |
| `system.agent_stopped` | The agent process stops |
| `system.key_rotated` | The agent rotates its signing key (old key seals the handoff, new key signs later checkpoints) |
| `system.key_revoked` | The agent records that a signing key must no longer be trusted; surfaces as an `F-KEYREV` finding |
| `system.network_outage` | The agent detects it lost connectivity to the store |
| `system.replay_completed` | A spooled backlog finishes uploading after an outage |
| `system.local_spool_pressure` | The local spool crosses a size/pressure threshold |
| `system.retention_policy_changed` | A store retention policy is created or changed |
| `system.retention_deleted` | Records are deleted under a retention policy |
| `system.legal_hold_placed` | A legal hold is placed on a source |
| `system.legal_hold_released` | A legal hold is released |

## Sending events

Go, using the `client` package:

```go
package main

import (
	"context"
	"log"

	"github.com/arhuman/prooflog/client"
)

func main() {
	c := client.New("127.0.0.1:9600")

	acc, err := c.Send(context.Background(), client.Event{
		Type:    client.EventDeployCompleted,
		Actor:   "ci@acme",
		Outcome: client.OutcomeSuccess,
		Payload: struct {
			Service string `json:"service"`
			Version string `json:"version"`
		}{Service: "api", Version: "1.2.3"},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("accepted seq=%d hash=%s", acc.Seq, acc.RecordHash)
}
```

The equivalent CLI call:

```sh
prooflog event deploy.completed \
  --actor ci@acme \
  --outcome success \
  --payload-json '{"service":"api","version":"1.2.3"}'
```
