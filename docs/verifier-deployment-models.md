# Verifier deployment models

The Verifier is the v1 trust anchor. How much a Prooflog report proves against the store operator depends entirely on how independent the Verifier is from that operator. This document describes four concrete deployment tiers, from zero independence to full third-party independence, and the orthogonal external anchoring axis that adds a time guarantee at any tier.

## The core principle

The Verifier's trust basis is **organizational independence**: the assurance that history cannot be rewritten undetected holds only when a party separate from the store operator does the checking. When one administrator runs agent, store, and verifier, that basis collapses. The strongest guarantee combines an independent verifier (catches rewrites via fork rejection, REQ-C-07) with external anchoring (proves existence-at-time via external attestation that does not require separation of powers). See [`docs/threat-model.md`](threat-model.md) for the threat posture and the "Anchor vs Verifier — two trust roles" section of [`docs/architecture.md`](architecture.md) for the role distinction.

## Deployment tiers

### Tier 0 — All-in-one (single administrator)

**Who controls what.** One operator runs agent, store, and verifier on the same or shared infrastructure.

**Defends against:**
- External attackers who have not compromised the host
- Accidental corruption: the hash chain and Merkle roots detect silent bit-rot
- Transport tampering: TLS is the default for all gRPC connections; `--insecure` is an explicit opt-in that prints a warning and must not be used in production
- Non-privileged users who cannot modify spool files or database rows

**Does NOT defend against:**
- The operator themselves; a single administrator with access to all three components can rewrite history undetected

**How to run it.** Start all three services on one host. The `prooflog demo` commands and `scripts/demo.sh` use this topology. Leave `--verifier-operator` empty or equal to the org name when generating the report; the report header is automatically marked `self-hosted — not independent from the storage operator`.

**Use it for.** Local development, the adversarial demo, and an operator's own operational records where the operator is the trusted party rather than a subject of scrutiny.

---

### Tier 1 — Separate host or account, same admin domain

**Who controls what.** The verifier runs on a distinct host or cloud account from the store; one person or team holds credentials to both environments.

**Defends against:**
- Everything in Tier 0
- A store-only compromise: once the verifier has accepted a checkpoint via fork rejection, an attacker who controls only the store cannot present a rewritten history without the verifier detecting the inconsistency on next verification

**Does NOT defend against:**
- An insider who holds credentials to both the store host and the verifier host; a single actor with both credential sets can subvert the verifier's accepted checkpoint state and substitute a forged one

**How to run it.** Deploy the verifier on its own host or cloud account with a separate `--data-dir`. Use TLS between all components (`--tls-cert`, `--tls-key`, `--tls-ca`; not `--insecure`). Pass a distinct `--verifier-operator` name to `prooflog report` so the report records a named operator rather than marking itself self-hosted.

```
# Verifier daemon on its own host
prooflog verifier \
  --listen 0.0.0.0:9800 \
  --store-addr store.internal:9700 \
  --data-dir /var/lib/prooflog-verifier \
  --keys /etc/prooflog/verifier-keys.json \
  --tls-cert /etc/certs/verifier.crt \
  --tls-key /etc/certs/verifier.key \
  --tls-ca /etc/certs/org-ca.crt

# Report generation (can run from anywhere with access to verifier data)
prooflog report \
  --verifier-operator acme-ops \
  --checkpoints /var/lib/prooflog-verifier \
  --keys /etc/prooflog/verifier-keys.json \
  ...
```

Adding the Anchor (`--tsa-url`, described below) at this tier preserves backdating resistance even if an attacker later gains access to both hosts; the TSA timestamp is already committed externally.

**Use it for.** Raising the assurance bar cheaply without a second legal entity, or as a stepping stone toward Tier 2.

---

### Tier 2 — Separate administrative authority (segregation of duties)

**Who controls what.** The verifier is operated by a different team with separate access control and change management, for example an internal audit function or a security operations team within the same organization.

**Defends against:**
- Everything in Tier 1
- A single insider acting alone: rewriting accepted history now requires subverting a separate team's access controls and overriding the verifier's fork-rejection state without that team's knowledge; collusion, not a single actor, becomes the requirement

**Does NOT defend against:**
- Collusion between the two teams
- Organization-level legal compulsion that affects both teams simultaneously

**How to run it.** The audit or security team manages the verifier host, its credentials, and its data directory independently, under separate IAM or access-control policies from the store operator's team. Enable mTLS client auth on the store so that legal hold placement and release are gated on transport identity: `prooflog store --tls-client-auth`. The flag `--allow-unauthenticated-holds` disables this gate and must not be used in production. Meaningful hold protection requires both the verifier-independent posture and mTLS client auth.

```
# Store side (operated by the store team)
prooflog store \
  --dir /var/lib/prooflog-store \
  --listen 0.0.0.0:9700 \
  --tls-cert /etc/certs/store.crt \
  --tls-key /etc/certs/store.key \
  --tls-ca /etc/certs/org-ca.crt \
  --tls-client-auth

# Verifier side (operated by the audit team, separate credentials)
prooflog verifier \
  --listen 0.0.0.0:9800 \
  --store-addr store.internal:9700 \
  --data-dir /var/lib/prooflog-verifier \
  --keys /etc/prooflog/verifier-keys.json \
  --tls-cert /etc/certs/verifier.crt \
  --tls-key /etc/certs/verifier.key \
  --tls-ca /etc/certs/org-ca.crt

# Report (issued by the audit team, naming itself as operator)
prooflog report \
  --verifier-operator "acme-internal-audit" \
  --verifier-locality EU/DE \
  --checkpoints /var/lib/prooflog-verifier \
  --keys /etc/prooflog/verifier-keys.json \
  ...
```

**Use it for.** Internal assurance programs, many internal audit contexts, and operational log integrity where a single rogue insider should not be able to rewrite history silently.

---

### Tier 3 — Separate legal entity (independent third party)

**Who controls what.** The verifier is operated by a distinct legal and administrative authority: a client, an MSP, or a hosted verifier provider. The store operator has no administrative access to the verifier infrastructure.

**Defends against:**
- Everything in Tier 2
- The store operator acting alone, or their entire team acting together: they cannot present a rewritten history without the third party detecting a fork, because the third party's verifier holds an independent record of accepted checkpoints and will reject any inconsistency (REQ-C-07)

**Does NOT defend against:**
- Events that were never emitted; the verifier witnesses what it received, not what the application could have sent
- The third-party verifier itself being compromised or colluding with the store operator
- Activity during observation gaps (see "What no tier proves" below)

**How to run it.** The third party runs `prooflog verifier` on infrastructure they control. Agents submit checkpoints directly to that verifier; this path bypasses the store, so a store-side compromise does not prevent the verifier from receiving the original checkpoints. The store operator cannot alter the third party's accepted checkpoint history. The third party issues the authoritative report naming themselves as `--verifier-operator`.

```
# Agent config.json must point to the third party's verifier address
prooflog agent --config config.json

# Third party runs the verifier on their own infrastructure
prooflog verifier \
  --listen 0.0.0.0:9800 \
  --store-addr store.client.example:9700 \
  --data-dir /var/lib/prooflog-verifier \
  --keys /etc/prooflog/verifier-keys.json \
  --tls-cert /etc/certs/verifier.crt \
  --tls-key /etc/certs/verifier.key \
  --tls-ca /etc/certs/ca.crt

# Third party issues the report
prooflog report \
  --verifier-operator "third-party-auditor" \
  --checkpoints /var/lib/prooflog-verifier \
  --keys /etc/prooflog/verifier-keys.json \
  ...
```

A hosted independent verifier option is on the roadmap for operators who want a third-party trust anchor without managing verifier infrastructure themselves.

**Use it for.** Evidence intended to be defensible against the store operator: client assurance packs, regulator-facing event timelines, and forensic export packages where the recipient is the verifying party.

---

## The orthogonal axis: external anchoring

The Anchor adds existence-at-time on top of any tier, including Tier 0. Its trust basis is external attestation, not separation of powers. An RFC 3161 TSA timestamps the exact bytes of a signed checkpoint; even an operator who controls all three components cannot backdate a checkpoint the TSA has already timestamped.

Enable it on the verifier:

```
prooflog verifier \
  --tsa-url https://freetsa.org/tsr \
  ...
```

The Anchor and the Verifier address orthogonal threats. The Anchor proves existence-at-time; the Verifier detects rewrites and continuity gaps. "Tier 0 + Anchor" resists backdating but does not resist a history rewrite by the administrator. "Tier 3 + Anchor" resists both.

RFC 3161 TSA anchoring is shipped. An eIDAS-qualified TSA (Art. 41 legal presumption of time and integrity) and Sigstore Rekor v2 remain on the roadmap under the same `Anchor` interface. See the "Anchor vs Verifier — two trust roles" section of [`docs/architecture.md`](architecture.md).

---

## What no tier proves

These limitations apply at every tier:

- **Never-emitted events.** If the application did not send an event, or the agent was not running, that event is absent. Prooflog proves the events it observed, not all events that could have occurred.
- **Activity during observation gaps.** The agent records `system.agent_stopped` on clean shutdown and `system.agent_started` on restart, bounding the gap. What occurred on the host during that window is outside the scope of Prooflog evidence.
- **Clock accuracy beyond recorded NTP drift.** The agent records NTP drift per heartbeat. Event ordering derives from sequence numbers, not timestamps; wall-clock accuracy is reported, not guaranteed.
- **Independence of declared operators and localities.** The `--verifier-operator` flag and the `--verifier-locality` / `--store-locality` flags record a chain-of-custody declaration in the report. They are not a cryptographic proof that the named operator is actually independent or that data physically resides in the declared jurisdiction.

---

## Quick chooser

| Use case | Recommended tier | Anchor? | Why |
|---|---|---|---|
| Local demo or development | Tier 0 | Optional | No trust claim needed; `prooflog demo` and `scripts/demo.sh` use this topology |
| Operator's own operational records (trusted operator) | Tier 0 or 1 | Recommended | Defends against external attack and accidental corruption; anchor resists backdating |
| Internal audit assurance | Tier 2 | Recommended | Segregation of duties makes a single insider insufficient; anchor adds time attestation |
| Client-facing or regulator-facing evidence | Tier 3 | Yes | A separate legal authority makes the report defensible against the store operator; eIDAS-qualified TSA (roadmap) adds the Art. 41 legal presumption of time |
