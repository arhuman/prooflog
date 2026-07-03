# 9. Store trust model — verify-at-ingest vs verify-only-offline

Date: 2026-07-05

## Status

Accepted

## Context

`UploadSegment` (`internal/store/store.go`) receives a segment header (`meta`)
followed by the frames of one source, persists the blob, and commits an index
row. Historically the store hash-verified each frame individually but performed
no cross-frame or header-level integrity check: a client could upload a segment
declaring an arbitrary Merkle `root` (proven by a test that uploaded an all-zero
root successfully) or a seq range that did not match the frames it sent. Such a
lie was only caught much later, downstream, when the offline verifier recomputed
roots against the signed checkpoint (`RootsValid`) — surfacing as a confusing
gap far from its cause.

This reflected an implicit stance: **the store is a dumb bag that persists
claims; verification is entirely the verifier's job.** That stance was never
written down, so its boundaries were unclear. The question this ADR settles:
*what should the store verify at ingest, and what does it deliberately defer?*

A key architectural fact constrains the answer. A segment's `meta.Root` is **not**
a subtree hash over the frames in that segment. It is the *cumulative* RFC 6962
tree root over the source's entire history `[1..seq_last]` (`segment.Batcher.Seal`
returns `b.tree.Root()` at the new tree size, and `meta.Checkpoint` is the C2SP
tlog-checkpoint signing exactly that `(size, root)`). The agent uploads only the
frames `[seq_first..seq_last]` for the segment, not the source's earlier frames.

Therefore the naive "recompute the root from the received frames and compare"
(the intuitive ingest check) is **infeasible**: the store lacks the earlier
frames in the stream, and reconstructing them from its own prior blobs would cost
O(history) per upload — precisely the scaling cost the design avoids elsewhere.

## Decision

The store performs the **cheap, in-hand** integrity checks at ingest and defers
the **expensive, cross-history** check to the offline verifier.

Verified at ingest (`validateMeta` + the `UploadSegment` frame loop):

1. **Root ↔ checkpoint binding.** Parse the signed checkpoint the segment
   carries (`note.CheckpointOf`, no signature verification) and reject unless its
   committed tree size equals `meta.SeqLast` and its committed root equals
   `meta.Root`. The store refuses to persist a root that contradicts the
   checkpoint it is persisting alongside it.
2. **Frame seq-contiguity and source binding.** Parse each persisted frame and
   reject unless its record carries the next contiguous seq within
   `[seq_first, seq_last]` and this segment's `source_id`. A short, over-long, or
   spliced stream is rejected.

Deferred to the offline verifier (unchanged):

3. **Cumulative-root recomputation.** Recompute each source's RFC 6962 root from
   the full pulled frame history and check it against the *signature-verified*
   checkpoint (`RootsValid`), and enforce append-only checkpoint consistency.
   Only the verifier holds the trusted public keys and the full history, so only
   the verifier can establish authenticity and cumulative integrity.

The store does **not** verify checkpoint signatures at ingest: it holds no pinned
per-source public keys (key distribution to the store is out of scope), so a
signature check there would be theatre. Binding root/size/seq to the in-hand
artifacts is the honest limit of what the store can cheaply assert.

### Rejected alternative — recompute root from received frames

The intuitive check ("`merkle.RootFromEntries(frames) == meta.Root`") was
rejected: `meta.Root` is a cumulative root over `[1..seq_last]`, so it equals
`RootFromEntries` only for the first segment of a source. Applying it would
reject every subsequent segment. Recomputing the *cumulative* root at ingest
would require the store to re-read all prior blobs of the source on every upload
(O(history) per upload) — an unacceptable steady-state cost, and redundant with
the verifier's offline pass.

## Consequences

**Positive.** The store now fails fast, with attribution (`InvalidArgument`),
instead of persisting an unverifiable claim. A buggy or partially-compromised
agent can no longer poison the index with a root or seq range that disagrees
with its own checkpoint. The trust boundary is now explicit
(`docs/trust-boundaries.md`) and reviewable.

**Negative.** Ingest now parses every frame's envelope (previously frames were
opaque bytes on the write path, parsed only on read-back). This is O(frames),
which the store already pays for per-frame hashing, and it aligns the write path
with the read path, which already assumed valid envelopes. Frames uploaded to the
store must now be well-formed records — a stricter contract, exercised by the
store tests.

**Neutral.** Authenticity (signature verification) and cumulative integrity
remain solely the verifier's responsibility; the store's checks are necessary,
not sufficient, and are documented as such.

## References

- `docs/trust-boundaries.md` — who verifies what, and why
- `docs/standards.md` REQ-E-04 (append-only, defined failure behavior),
  REQ-C-07 (tlog-checkpoint commitment), REQ-E-05 (verifiable by digest)
- `internal/store/store.go` — `validateMeta`, `UploadSegment`
- `internal/store/upload_validation_test.go` — `TestUploadRejectsRootMismatch`,
  `TestUploadRejectsCheckpointSizeMismatch`, `TestUploadRejectsSeqRangeMismatch`
- ADR-0004 — cryptographic construction (cumulative RFC 6962 tree, checkpoints)
