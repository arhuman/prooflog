# Prooflog threat model

Read this document before trusting any Prooflog report. The security claims depend entirely on how the system is deployed.

## Posture: tamper-evident, not tamper-proof

Prooflog follows the Common Criteria FAU_STG.2 "detect" posture: it prevents unauthorized deletion from the local spool and detects unauthorized modification of any accepted event. It does not make tampering impossible for a sufficiently privileged adversary. "Tamper-evident" means you can tell something was changed, after the fact. "Tamper-proof" would be a stronger claim that this system does not make.

## What tampering is detectable, and under what condition

The following are detectable when the verifier is operated by an independent party and received the original signed checkpoints directly from the agent before any tampering occurred:

- Modification of any accepted event: the hash chain and the Merkle root of its segment break.
- Deletion of any accepted event: the sequence gap is reported; the hash chain breaks.
- Insertion of a forged event retroactively into an already-sealed segment: the Merkle root changes.
- Truncation of the log: the verifier rejects any new checkpoint with a tree size smaller than a previously accepted one for that source.
- Reordering of events within a sealed segment: the hash chain breaks.
- Observation gaps: missing heartbeats beyond the configured silence threshold are reported as findings.

Detection requires verifier independence. If the same administrator controls both the store and the verifier, the above guarantees do not hold.

## Self-hosted caveat

When one administrator controls all three components — agent, store, and verifier — that administrator can rewrite history undetected. The verifier's trust anchor is not independent of the operator it is supposed to check. Reports generated from such a deployment must state this limitation explicitly; Prooflog does so in the report header. The recommended deployment for meaningful assurance is a Verifier operated under a separate legal and administrative authority from the Store operator — an internal audit team, a client, an MSP, or a hosted verifier provider.

The `Anchor` interface addresses exactly this case: it provides external timestamping that does not depend on verifier independence. Its RFC 3161 TSA implementation is shipped (`prooflog verifier --tsa-url`); an eIDAS-qualified TSA and Sigstore Rekor remain on the roadmap. See docs/architecture.md, "Anchor vs Verifier — two trust roles".

See [`verifier-deployment-models.md`](verifier-deployment-models.md) for concrete deployment tiers.

## Transport security

TLS is the default for all gRPC connections between components. Passing `--insecure` to any server or client command is an explicit opt-in; the component prints a one-line warning to stderr so plaintext transport is never silent. Use `--insecure` only for loopback demos. Production deployments should configure `--tls-cert`, `--tls-key`, and `--tls-ca`.

## Legal-hold and retention trust model

Hold place and release RPCs are gated on transport identity, not a separate credential: the store denies them unless the caller presented an mTLS-verified client certificate (`prooflog store --tls-client-auth`). Passing `--allow-unauthenticated-holds` disables this check for loopback demos, and the store warns at startup that any caller reaching the socket can then place or release holds. Read-only hold and tombstone listings stay open because the verifier depends on them. Meaningful hold protection still requires the verifier-independent operator posture described above in addition to mTLS client auth.

## What a compromised agent key can and cannot do

An attacker who obtains an agent's Ed25519 private key can produce credibly signed events for that source going forward. They cannot retroactively alter events already covered by a checkpoint that the independent verifier has accepted: the fork-rejection rule prevents the verifier from accepting any new checkpoint inconsistent with its history. The exposure window runs from the moment of compromise to the moment the `system.key_revoked` event is recorded and the key is retired. That window appears as an explicit `F-KEYREV` finding (severity high) in any report covering that period, naming the revoked key ID and the suspected-exposure start.

Recovery is a rotation, not a break in the chain. `prooflog key rotate` emits a `system.key_rotated` event and seals the tree covering it under the OLD key (the outgoing key attests the handoff), then signs every later checkpoint with the new key. Because the Merkle tree is unbroken and both public keys are registered with the verifier, the rotated chain still verifies CLEAN — the key change is not tampering. Operators typically rotate first, then revoke the old key, so a trusted key is always in place.

## What is out of scope

Prooflog cannot prove the absence of events that were never emitted. If an application does not send an event, or if the agent is not running, those events are simply absent from the log.

When the agent is not running, observation is bounded, not silent. The agent records `system.agent_stopped` on clean shutdown and `system.agent_started` on restart. The gap between those two events is bounded: the system can prove exactly when observation stopped and when it resumed. What happened on the host during that window cannot be proven or disproven from Prooflog data alone (see [`examples/continuity-report.md`](../examples/continuity-report.md) §3.1 for a worked example of a bounded gap with recommendations).

Clock accuracy is checkable, not guaranteed. The agent records NTP clock drift in each heartbeat. Event ordering derives from sequence numbers, not timestamps.
