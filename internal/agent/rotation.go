package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/segment"
)

// RotationResult reports the outcome of a signing-key rotation so the caller can
// print registration instructions. The new public key must be registered with
// the verifier operator before its checkpoints can be trusted (REQ-C-07,
// REQ-C-11).
type RotationResult struct {
	OldKeyID        string `json:"old_key_id"`
	NewKeyID        string `json:"new_key_id"`
	NewKeyName      string `json:"new_key_name"`
	NewPublicKeyB64 string `json:"new_public_key"`
	Origin          string `json:"origin"`
	SourceID        string `json:"source_id"`
}

// nextKeyName derives the next generation's signing name from the current one by
// appending or incrementing a "-g<N>" suffix (e.g. "api" -> "api-g2" ->
// "api-g3"). The name MUST change every rotation: the C2SP key id hashes the
// name together with the public key, and the offline keyring is keyed by name.
func nextKeyName(name string) string {
	base, gen := name, 1
	if i := strings.LastIndex(name, "-g"); i >= 0 {
		if n, err := strconv.Atoi(name[i+2:]); err == nil && n >= 1 {
			base, gen = name[:i], n
		}
	}
	return fmt.Sprintf("%s-g%d", base, gen+1)
}

// RotateKey rotates the agent's Ed25519 signing key. The whole handoff runs
// under a.mu so seq, chain head, batcher, and spool stay consistent:
//
//  1. generate a fresh key with a new distinct name;
//  2. emit a system.key_rotated event as the next leaf, naming both key ids;
//  3. force-seal the current tree under the OLD key, so the checkpoint covering
//     the key_rotated event is signed by the outgoing key — a cryptographic
//     attestation of the handoff by the key being retired;
//  4. persist the new key to the agent key path and swap the batcher's signer so
//     every later checkpoint is signed by the new key.
//
// The old public key is not removed anywhere: it stays registered with the
// verifier so historical checkpoints keep verifying, which is what keeps a
// rotated chain verifiable-clean (REQ-C-07, REQ-C-11).
func (a *Agent) RotateKey(reason string) (RotationResult, error) {
	a.mu.Lock()

	oldKey := a.agentKey
	oldName := oldKey.Name
	newName := nextKeyName(oldName)
	newKey, err := keys.GenerateAgentKey(newName, time.Now())
	if err != nil {
		a.mu.Unlock()
		return RotationResult{}, fmt.Errorf("agent: generate rotated key: %w", err)
	}
	oldKeyID := oldKey.KeyIDHex()
	newKeyID := newKey.KeyIDHex()

	var sealedSegs []segment.Sealed
	_, sealed, err := a.emitSystemLocked(EventKeyRotated, map[string]any{
		"old_key_id":   oldKeyID,
		"old_key_name": oldName,
		"new_key_id":   newKeyID,
		"new_key_name": newName,
		"reason":       reason,
	})
	if err != nil {
		a.mu.Unlock()
		return RotationResult{}, fmt.Errorf("agent: emit key_rotated: %w", err)
	}
	if sealed != nil {
		sealedSegs = append(sealedSegs, *sealed)
	}
	// Force-seal any remaining pending records under the OLD signer so the
	// checkpoint covering the key_rotated event is signed by the outgoing key.
	if a.batcher.Pending() > 0 {
		s, err := a.batcher.Seal(time.Now())
		if err != nil {
			a.mu.Unlock()
			return RotationResult{}, fmt.Errorf("agent: seal under old key: %w", err)
		}
		sealedSegs = append(sealedSegs, s)
	}
	// Persist the new key before swapping the in-memory signer: if the write
	// fails the batcher keeps signing under the old key (still registered and
	// consistent), and only a harmless informational key_rotated event remains.
	if err := keys.SaveAgentKey(a.cfg.AgentKeyPath, newKey); err != nil {
		a.mu.Unlock()
		return RotationResult{}, fmt.Errorf("agent: persist rotated key: %w", err)
	}
	a.batcher.SetSigner(newName, newKey.Private)
	a.agentKey = newKey
	origin, sourceID := a.origin, a.cfg.SourceID
	a.mu.Unlock()

	for _, s := range sealedSegs {
		a.enqueue(s)
	}
	a.log.Info("signing key rotated",
		"old_key_id", oldKeyID, "new_key_id", newKeyID, "new_key_name", newName, "reason", reason)

	return RotationResult{
		OldKeyID:        oldKeyID,
		NewKeyID:        newKeyID,
		NewKeyName:      newName,
		NewPublicKeyB64: base64.StdEncoding.EncodeToString(newKey.Public),
		Origin:          origin,
		SourceID:        sourceID,
	}, nil
}

// RevokeKey records that the agent's current signing key must no longer be
// trusted, emitting a system.key_revoked event into the source's own chain. It
// records the boundary only — it does NOT generate a new key. Operators normally
// rotate first (so a trusted key is already in place) and then revoke the old
// one, or rotate afterwards; either way the exposure window surfaces as an
// F-KEYREV finding in any report covering the period (REQ-C-11).
func (a *Agent) RevokeKey(reason, suspectedSince string) (envelope.Record, error) {
	a.mu.Lock()
	revokedKeyID := a.agentKey.KeyIDHex()
	rec, sealed, err := a.emitSystemLocked(EventKeyRevoked, map[string]any{
		"revoked_key_id":   revokedKeyID,
		"revoked_key_name": a.agentKey.Name,
		"reason":           reason,
		"suspected_since":  suspectedSince,
	})
	a.mu.Unlock()
	if err != nil {
		return envelope.Record{}, fmt.Errorf("agent: emit key_revoked: %w", err)
	}
	if sealed != nil {
		a.enqueue(*sealed)
	}
	a.log.Warn("signing key revoked",
		"revoked_key_id", revokedKeyID, "reason", reason, "suspected_since", suspectedSince)
	return rec, nil
}

// emitSystemLocked appends a system.* event with a clear payload assuming a.mu is
// held, returning any segment sealed as a result for the caller to enqueue
// outside the lock (REQ-E-09).
func (a *Agent) emitSystemLocked(eventType string, payload any) (envelope.Record, *segment.Sealed, error) {
	clearPayload, err := json.Marshal(payload)
	if err != nil {
		return envelope.Record{}, nil, fmt.Errorf("agent: marshal %s payload: %w", eventType, err)
	}
	in := EventInput{EventType: eventType, Payload: clearPayload}
	return a.acceptLocked(func(seq uint64, prev string, now time.Time) (envelope.Record, error) {
		return a.buildRecord(in, seq, prev, now)
	})
}
