// Package verifier runs the offline verification algorithm (architecture §7)
// over a source's records and signed checkpoints: signatures, append-only
// consistency, root recomputation, hash-chain linkage, observation continuity,
// and transport tolerance (REQ-C-02, REQ-C-07, REQ-E-05).
package verifier

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
	"time"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/evidence"
	"github.com/arhuman/prooflog/internal/hashid"
	"github.com/arhuman/prooflog/internal/merkle"
	"github.com/arhuman/prooflog/internal/note"
)

// System event types used by the continuity and transport checks (objectif §10).
const (
	evHeartbeat    = "system.heartbeat"
	evAgentStarted = "system.agent_started"
	evAgentStopped = "system.agent_stopped"
	evOutage       = "system.network_outage"
	evReplay       = "system.replay_completed"
	evKeyRotated   = "system.key_rotated"
	evKeyRevoked   = "system.key_revoked"
)

// Keyring maps a signing-key name to its registered Ed25519 public key
// (REQ-C-07 step 1).
type Keyring map[string]ed25519.PublicKey

// Policy sets the continuity and clock thresholds a source is checked against.
type Policy struct {
	HeartbeatInterval time.Duration
	MaxSilence        time.Duration
	MaxClockDriftMS   int64
}

// DefaultPolicy is the v1 policy: 60s heartbeats, 3m max silence, 1s max drift.
func DefaultPolicy() Policy {
	return Policy{HeartbeatInterval: 60 * time.Second, MaxSilence: 3 * time.Minute, MaxClockDriftMS: 1000}
}

// Source is the verification input for one source: its ordered record frames and
// the signed checkpoints received for it.
type Source struct {
	SourceID    string
	Origin      string
	Entries     []chain.Entry
	Checkpoints []string
	Anchors     []anchor.Receipt
	Tombstones  []TombstoneInfo
}

// TombstoneInfo is a store-agnostic view of a retention tombstone: a segment
// whose blob was deleted under policy, but whose seq range and Merkle root
// survive so the verifier reports an expired-but-retained range instead of a
// false gap (WS6). It carries no store dependency to avoid an import cycle.
type TombstoneInfo struct {
	SegmentID string
	SeqFirst  uint64
	SeqLast   uint64
	Root      []byte
	Policy    string
}

// ChainCheck reports hash-chain verification (§7 step 4).
type ChainCheck struct {
	Valid bool
	Err   error
}

// CheckpointCheck reports checkpoint signatures, root recomputation, and
// append-only consistency (§7 steps 1-3).
type CheckpointCheck struct {
	Total           int
	SignaturesValid int
	RootsValid      int
	Consistent      bool
}

// AnchorCheck reports external RFC 3161 timestamp receipts cross-checked against
// the accepted checkpoints: each receipt's imprint must equal SHA-256 of an
// accepted signed checkpoint note, and its (origin, size, root) must match that
// checkpoint (REQ-C-15). Unmatched receipts raise F-ANCHOR.
type AnchorCheck struct {
	Total         int       // receipts presented
	Matching      int       // receipts bound to an accepted checkpoint
	LatestGenTime time.Time // most recent authority-attested genTime among matches
	TSA           string
	Qualified     bool
	Configured    bool // any receipts present
	// SignatureVerified is true only when the TSA token's CMS signature and
	// certificate chain were verified in-process. It stays false: verifyAnchors
	// checks the imprint and nonce round-trip but not the token signature, which
	// remains externally verifiable via `openssl ts -verify` (REQ-C-15).
	SignatureVerified bool
}

// Window is an interval between heartbeats exceeding the max silence.
type Window struct {
	Start    time.Time
	End      time.Time
	Duration time.Duration
	Bounded  bool
}

// ContinuityCheck reports heartbeat-derived observability (§7 step 5).
type ContinuityCheck struct {
	Summary evidence.ContinuitySummary
	Windows []Window
}

// TransportCheck reports outage/replay tolerance (§7 step 6).
type TransportCheck struct {
	Outages         int
	LongestOutage   time.Duration
	BufferedEvents  uint64
	ReplayCompleted bool
}

// KeyRevocation is a signing-key revocation recorded in the source's own chain
// by a system.key_revoked event. It marks the boundary after which the named
// key must no longer be trusted; events it signed within the suspected-exposure
// window are surfaced as an F-KEYREV finding (threat model §"compromised agent
// key").
type KeyRevocation struct {
	RevokedKeyID   string
	RevokedKeyName string
	Reason         string
	SuspectedSince string
	Seq            uint64
	EventTime      time.Time
}

// SourceResult is the full verification result for one source.
type SourceResult struct {
	SourceID        string
	Origin          string
	SeqFirst        uint64
	SeqLast         uint64
	TimeFirst       time.Time
	TimeLast        time.Time
	ChainHead       string
	KeyID           string
	Encrypted       bool
	EventCounts     []evidence.EventCount
	Chain           ChainCheck
	Checkpoints     CheckpointCheck
	Anchors         AnchorCheck
	Continuity      ContinuityCheck
	Transport       TransportCheck
	MaxClockDriftMS int64
	Revocations     []KeyRevocation
	Findings        []evidence.Finding
	Inputs          evidence.InputAttestation
	Retention       evidence.RetentionSummary
}

// Verify runs all checks for one source against keys and policy (§7). It drives a
// single streaming fold over src.Entries; the daemon feeds the exact same fold
// from its pull stream (P3), so an in-memory Source and a bounded stream yield
// byte-identical SourceResults.
func Verify(src Source, keys Keyring, policy Policy) SourceResult {
	f := newSourceFold(src.SourceID, src.Origin, src.Checkpoints, src.Anchors, src.Tombstones, keys, policy)
	for _, e := range src.Entries {
		f.add(e)
	}
	return f.result()
}

// StreamVerifier folds a source's record frames one at a time into a
// SourceResult without retaining them, so a source can be verified from a
// bounded pull stream (P3). It drives the exact same fold Verify runs over an
// in-memory slice, so a stream and an equivalent in-memory Source yield a
// byte-identical SourceResult. It is the transport-free seam a gRPC daemon feeds
// from its pull stream, keeping the offline engine free of any transport import.
type StreamVerifier struct{ f *sourceFold }

// NewStreamVerifier begins a streaming verification for one source. The
// non-entry inputs (checkpoints, anchors, tombstones, keys, policy) are fixed up
// front exactly as Verify fixes them; entries are supplied later via Add. The
// src.Entries field is ignored — entries arrive through Add, not the slice.
func NewStreamVerifier(src Source, keys Keyring, policy Policy) *StreamVerifier {
	return &StreamVerifier{
		f: newSourceFold(src.SourceID, src.Origin, src.Checkpoints, src.Anchors, src.Tombstones, keys, policy),
	}
}

// Add folds one record frame in arrival order, retaining none.
func (s *StreamVerifier) Add(e chain.Entry) { s.f.add(e) }

// Result finalizes the fold into the source's complete SourceResult.
func (s *StreamVerifier) Result() SourceResult { return s.f.result() }

// systemBucket groups non-heartbeat system.* events in the evidence summary.
const systemBucket = "system.* (heartbeats excluded)"

// checkpointRoot is a signature-valid checkpoint's committed (size, root).
type checkpointRoot struct {
	size uint64
	root [32]byte
}

// sourceFold accumulates every entry- and record-derived check in a single
// left-to-right pass so a source can be verified from a bounded stream without
// materialising all its frames (P3). Verify feeds it the full slice;
// Daemon.verifySource feeds it the pull stream one frame at a time. Both share
// this one fold, so both produce a byte-identical SourceResult.
//
// Memory is O(1) in the raw frame bytes and parsed records — the terms that used
// to grow with the frame count and tripped the maxPull cliff. Checkpoints,
// anchors and tombstones are bounded, non-entry inputs and are handled exactly as
// before at result() time. The Merkle root recomputation folds an incremental
// RFC 6962 hasher (O(log n) state) and snapshots Root() only at the tree sizes
// the checkpoints claim, so no leaf array is retained. Two small folds still keep
// one value per *relevant* record — the heartbeat timestamps (for the sort-based
// gap semantics) and the accumulated findings — both far smaller than, and
// independent of, the frame bytes they replace.
type sourceFold struct {
	sourceID string
	origin   string
	policy   Policy
	keys     Keyring

	checkpoints []string
	anchors     []anchor.Receipt
	tombstones  []TombstoneInfo

	// parse short-circuit: a single unparseable frame collapses the result to a
	// lone F-CHAIN, exactly as the original early return did.
	idx      int
	parseErr error

	// record span / head
	n         int
	haveRec   bool
	seqFirst  uint64
	seqLast   uint64
	chainHead string
	timeFirst time.Time
	timeLast  time.Time

	// privacy posture (REQ-C-08)
	keyID     string
	encrypted bool

	// event counts (first-appearance order, sorted at result time)
	evCounts map[string]int
	evOrder  []string

	// continuity: heartbeat instants and the beat indices followed by a clean stop
	beats []time.Time
	stops map[int]bool

	// transport outage/replay fold
	tr         TransportCheck
	outageOpen bool
	outageTime time.Time
	outageSeq  uint64

	// trust boundaries and clock drift
	revocations []KeyRevocation
	maxDrift    int64

	// input attestation digest over the ordered record hashes (REQ-E-02)
	digest hash.Hash

	// hash-chain fold (mirrors verifyChain / verifyChainAcrossTombstones)
	hasTombstones bool
	covered       []interval
	chainErr      error
	chainSeen     int
	prevHash      string
	prevSeq       uint64

	// checkpoint Merkle fold (mirrors the no-tombstone branch of verifyCheckpoints)
	sigValid   int
	candidates []checkpointRoot
	mh         merkle.Hasher
	rootAt     map[uint64][32]byte
	needSize   map[uint64]bool
}

// newSourceFold pre-verifies checkpoint signatures once — the only entry-
// independent input to checkpoint verification — so the Merkle fold knows which
// tree sizes it must snapshot Root() at, and merges tombstone ranges up front.
func newSourceFold(sourceID, origin string, checkpoints []string, anchors []anchor.Receipt,
	tombstones []TombstoneInfo, keys Keyring, policy Policy) *sourceFold {
	f := &sourceFold{
		sourceID:      sourceID,
		origin:        origin,
		policy:        policy,
		keys:          keys,
		checkpoints:   checkpoints,
		anchors:       anchors,
		tombstones:    tombstones,
		evCounts:      map[string]int{},
		stops:         map[int]bool{},
		digest:        sha256.New(),
		hasTombstones: len(tombstones) > 0,
		prevHash:      chain.Genesis,
		rootAt:        map[uint64][32]byte{},
		needSize:      map[uint64]bool{},
	}
	for _, signed := range checkpoints {
		cp, ok := verifyCheckpointSig(signed, keys)
		if !ok {
			continue
		}
		f.sigValid++
		if !f.hasTombstones {
			f.candidates = append(f.candidates, checkpointRoot{cp.Size, cp.Hash})
			f.needSize[cp.Size] = true
		}
	}
	if f.hasTombstones {
		f.covered = mergeTombstoneRanges(tombstones)
	} else if f.needSize[0] {
		f.rootAt[0] = f.mh.Root() // empty-tree root, before any leaf
	}
	return f
}

// add folds one frame. A parse failure short-circuits every later fold: the
// result collapses to a lone F-CHAIN, matching the original parseRecords early
// return (the first unparseable frame wins).
func (f *sourceFold) add(e chain.Entry) {
	i := f.idx
	f.idx++
	if f.parseErr != nil {
		return
	}
	rec, err := envelope.Parse(e.Bytes)
	if err != nil {
		f.parseErr = fmt.Errorf("verifier: entry %d: %w", i, err)
		return
	}
	f.foldChain(e, rec)
	f.foldRecord(rec)
	if !f.hasTombstones {
		f.mh.Add(merkle.LeafHash(e.Bytes))
		if f.needSize[f.mh.Size()] {
			f.rootAt[f.mh.Size()] = f.mh.Root()
		}
	}
}

// foldChain advances the hash chain one frame, stopping at the first break so the
// structured error matches chain.Verify / verifyChainAcrossTombstones exactly.
func (f *sourceFold) foldChain(e chain.Entry, rec envelope.Record) {
	if f.chainErr != nil {
		return
	}
	sum := sha256.Sum256(e.Bytes)
	computed := hex.EncodeToString(sum[:])
	if computed != e.Hash {
		f.chainErr = &chain.HashError{Seq: f.prevSeq + 1, ClaimedHash: e.Hash, ComputedHash: computed}
		return
	}
	if f.hasTombstones {
		switch {
		case rec.Seq == f.prevSeq+1:
			if rec.PrevHash != f.prevHash {
				f.chainErr = &chain.LinkError{Seq: rec.Seq, ExpectedPrev: f.prevHash, GotPrev: rec.PrevHash}
				return
			}
		case rec.Seq > f.prevSeq+1 && rangeCovered(f.covered, f.prevSeq+1, rec.Seq-1):
			// A retention-deleted gap: the linking record is gone by policy, so we
			// cannot (and need not) verify the prev_hash across it.
		default:
			f.chainErr = &chain.GapError{ExpectedSeq: f.prevSeq + 1, GotSeq: rec.Seq}
			return
		}
	} else {
		if f.chainSeen > 0 && rec.Seq != f.prevSeq+1 {
			f.chainErr = &chain.GapError{ExpectedSeq: f.prevSeq + 1, GotSeq: rec.Seq}
			return
		}
		if rec.PrevHash != f.prevHash {
			f.chainErr = &chain.LinkError{Seq: rec.Seq, ExpectedPrev: f.prevHash, GotPrev: rec.PrevHash}
			return
		}
	}
	f.prevHash = computed
	f.prevSeq = rec.Seq
	f.chainSeen++
}

// foldRecord accumulates every record-derived summary for one parsed record.
func (f *sourceFold) foldRecord(rec envelope.Record) {
	f.n++
	if !f.haveRec {
		f.haveRec = true
		f.seqFirst = rec.Seq
	}
	f.seqLast = rec.Seq
	f.chainHead = rec.HashHex()

	if t, err := envelope.ParseTime(rec.EventTime); err == nil {
		if f.timeFirst.IsZero() || t.Before(f.timeFirst) {
			f.timeFirst = t
		}
		if t.After(f.timeLast) {
			f.timeLast = t
		}
	}

	if rec.PayloadCT != "" {
		f.encrypted = true
	}
	if f.keyID == "" && rec.KeyID != "" {
		f.keyID = rec.KeyID
	}

	f.foldEventCount(rec)
	f.foldContinuity(rec)
	f.foldTransport(rec)
	f.foldRevocation(rec)
	f.foldClockDrift(rec)

	h := rec.Hash()
	f.digest.Write(h[:])
}

// foldEventCount tallies event types for the evidence summary. Heartbeats are
// excluded and remaining system.* events are grouped, mirroring the target
// report's §6 layout (visible envelope metadata only, REQ-E-01).
func (f *sourceFold) foldEventCount(rec envelope.Record) {
	if rec.EventType == evHeartbeat {
		return
	}
	key := rec.EventType
	if rec.IsSystem() {
		key = systemBucket
	}
	if _, seen := f.evCounts[key]; !seen {
		f.evOrder = append(f.evOrder, key)
	}
	f.evCounts[key]++
}

func (f *sourceFold) foldContinuity(rec envelope.Record) {
	switch rec.EventType {
	case evHeartbeat:
		if t, err := envelope.ParseTime(rec.EventTime); err == nil {
			f.beats = append(f.beats, t)
		}
	case evAgentStopped:
		f.stops[len(f.beats)-1] = true // index into beats after which a clean stop occurred
	}
}

func (f *sourceFold) foldTransport(rec envelope.Record) {
	switch rec.EventType {
	case evOutage:
		f.tr.Outages++
		f.outageOpen = true
		f.outageSeq = rec.Seq
		if t, err := envelope.ParseTime(rec.EventTime); err == nil {
			f.outageTime = t
		}
	case evReplay:
		if !f.outageOpen {
			return
		}
		f.outageOpen = false
		f.tr.ReplayCompleted = true
		if rec.Seq > f.outageSeq+1 {
			f.tr.BufferedEvents += rec.Seq - f.outageSeq - 1
		}
		if t, err := envelope.ParseTime(rec.EventTime); err == nil {
			if d := t.Sub(f.outageTime); d > f.tr.LongestOutage {
				f.tr.LongestOutage = d
			}
		}
	}
}

// foldRevocation collects every system.key_revoked event from the source's own
// chain. Key rotation and revocation events are ordinary system records: they do
// not affect chain or continuity checks, they only record trust boundaries.
func (f *sourceFold) foldRevocation(rec envelope.Record) {
	if rec.EventType != evKeyRevoked {
		return
	}
	var p keyRevokedPayload
	if len(rec.PayloadClear) > 0 {
		_ = json.Unmarshal(rec.PayloadClear, &p)
	}
	kr := KeyRevocation{
		RevokedKeyID:   p.RevokedKeyID,
		RevokedKeyName: p.RevokedKeyName,
		Reason:         p.Reason,
		SuspectedSince: p.SuspectedSince,
		Seq:            rec.Seq,
	}
	if t, err := envelope.ParseTime(rec.EventTime); err == nil {
		kr.EventTime = t
	}
	f.revocations = append(f.revocations, kr)
}

func (f *sourceFold) foldClockDrift(rec envelope.Record) {
	if rec.EventType != evHeartbeat || len(rec.PayloadClear) == 0 {
		return
	}
	var p hbPayload
	if err := json.Unmarshal(rec.PayloadClear, &p); err != nil {
		return
	}
	drift := p.Health.ClockDriftMS
	if drift < 0 {
		drift = -drift
	}
	if drift > f.maxDrift {
		f.maxDrift = drift
	}
}

// result finalizes the fold into a complete SourceResult, identical to the
// original Verify assembly. A parse failure returns the same minimal result the
// original early return produced.
func (f *sourceFold) result() SourceResult {
	res := SourceResult{SourceID: f.sourceID, Origin: f.origin}
	if f.parseErr != nil {
		res.Chain = ChainCheck{Valid: false, Err: f.parseErr}
		res.Findings = append(res.Findings, integrityFinding("F-CHAIN", "record parse failed", f.parseErr.Error()))
		return res
	}
	if f.haveRec {
		res.SeqFirst = f.seqFirst
		res.SeqLast = f.seqLast
		res.ChainHead = f.chainHead
	}
	res.TimeFirst, res.TimeLast = f.timeFirst, f.timeLast
	res.KeyID, res.Encrypted = f.keyID, f.encrypted
	res.EventCounts = f.eventCounts()

	res.Chain = f.chainCheck()
	res.Checkpoints = f.checkpointCheck()
	res.Anchors = verifyAnchors(f.checkpoints, f.anchors, f.keys)
	res.Continuity = f.continuityCheck()
	res.Transport = f.transportCheck()
	res.Revocations = f.revocations
	res.MaxClockDriftMS = f.maxDrift
	res.Inputs = f.inputAttestation()
	res.Retention = verifyRetention(f.tombstones, f.checkpoints, f.keys)

	res.Findings = append(res.Findings, buildFindings(f.sourceID, res, f.policy)...)
	return res
}

func (f *sourceFold) chainCheck() ChainCheck {
	if f.chainErr != nil {
		return ChainCheck{Valid: false, Err: f.chainErr}
	}
	return ChainCheck{Valid: true}
}

// checkpointCheck reproduces verifyCheckpoints from the folded state. With
// tombstones the retained signed checkpoints are the commitment (WS6): verify
// signatures only. Otherwise each candidate root is compared against the Root()
// snapshot taken when the incremental hasher reached that tree size; a size larger
// than the leaves we streamed has no snapshot and cannot be validated — the same
// semantics as the previous bounds check.
func (f *sourceFold) checkpointCheck() CheckpointCheck {
	check := CheckpointCheck{Total: len(f.checkpoints), SignaturesValid: f.sigValid, Consistent: true}
	if f.hasTombstones {
		check.RootsValid = f.sigValid
		check.Consistent = f.sigValid == check.Total
		return check
	}
	for _, cand := range f.candidates {
		root, ok := f.rootAt[cand.size]
		if !ok {
			continue
		}
		if root == cand.root {
			check.RootsValid++
		}
	}
	// Every recomputed root was folded from the same leaf prefix, so pairwise
	// prefix consistency between accepted checkpoints is implied — generating and
	// verifying a ConsistencyProof over those same leaves could only fail on a
	// merkle-implementation bug, not on tampering. VerifyConsistency remains
	// exercised by the merkle unit tests and the checkpoint-daemon path (REQ-C-02).
	if check.SignaturesValid != check.Total || check.RootsValid != check.SignaturesValid {
		check.Consistent = check.Total == 0
	}
	return check
}

func (f *sourceFold) continuityCheck() ContinuityCheck {
	var check ContinuityCheck
	check.Summary.IntervalSeconds = int(f.policy.HeartbeatInterval.Seconds())
	check.Summary.MaxSilence = f.policy.MaxSilence
	check.Summary.Observed = len(f.beats)
	if len(f.beats) == 0 {
		return check
	}
	beats := f.beats
	sort.Slice(beats, func(i, j int) bool { return beats[i].Before(beats[j]) })

	// Expected heartbeats are derived from the observed window: the first
	// heartbeat to the last recorded event (a later event proves the source was
	// still expected to beat), divided by the interval, floored, minimum one.
	windowEnd := beats[len(beats)-1]
	if f.timeLast.After(windowEnd) {
		windowEnd = f.timeLast
	}
	window := windowEnd.Sub(beats[0])
	if f.policy.HeartbeatInterval > 0 {
		expected := int(window / f.policy.HeartbeatInterval)
		if expected < 1 {
			expected = 1
		}
		check.Summary.Expected = expected
	}

	var longest time.Duration
	for i := 1; i < len(beats); i++ {
		gap := beats[i].Sub(beats[i-1])
		if gap > longest {
			longest = gap
		}
		if gap > f.policy.MaxSilence {
			check.Windows = append(check.Windows, Window{
				Start:    beats[i-1],
				End:      beats[i],
				Duration: gap,
				Bounded:  f.stops[i-1],
			})
		}
	}
	check.Summary.LongestGap = longest
	check.Summary.WithinPolicy = longest <= f.policy.MaxSilence
	return check
}

func (f *sourceFold) transportCheck() TransportCheck {
	tr := f.tr
	if tr.Outages > 0 && f.outageOpen {
		tr.ReplayCompleted = false
	}
	return tr
}

func (f *sourceFold) eventCounts() []evidence.EventCount {
	sort.Strings(f.evOrder)
	out := make([]evidence.EventCount, 0, len(f.evOrder))
	for _, k := range f.evOrder {
		out = append(out, evidence.EventCount{Type: k, Count: f.evCounts[k]})
	}
	return out
}

// inputAttestation pins the exact evidence a source's verdict was computed from:
// the record count, a SHA-256 over the ordered per-record 32-byte hashes, and a
// citable id per accepted checkpoint (REQ-E-02, §5.5).
func (f *sourceFold) inputAttestation() evidence.InputAttestation {
	att := evidence.InputAttestation{RecordCount: f.n}
	att.InputDigest = hex.EncodeToString(f.digest.Sum(nil))
	for _, signed := range f.checkpoints {
		cp, ok := verifyCheckpointSig(signed, f.keys)
		if !ok {
			continue
		}
		att.CheckpointIDs = append(att.CheckpointIDs, checkpointID(cp))
	}
	return att
}

// verifyRetention summarizes the source's tombstones and checks each expired
// segment's root against the accepted checkpoint roots. RootsRetained is true
// only when every tombstone's root matches an accepted checkpoint, keeping the
// deleted range verifiable-by-commitment; a mismatch drives F-RETENTION.
func verifyRetention(tombstones []TombstoneInfo, checkpoints []string, keys Keyring) evidence.RetentionSummary {
	summary := evidence.RetentionSummary{ExpiredSegments: len(tombstones)}
	if len(tombstones) == 0 {
		return summary
	}
	roots := acceptedRoots(checkpoints, keys)
	summary.RootsRetained = true
	for _, t := range tombstones {
		summary.ExpiredRanges = append(summary.ExpiredRanges,
			fmt.Sprintf("seq %d-%d", t.SeqFirst, t.SeqLast))
		tr, err := hashid.ParseDigest(t.Root)
		if err != nil || !roots[tr] {
			summary.RootsRetained = false
		}
	}
	return summary
}

// acceptedRoots collects the RFC 6962 roots of every signature-valid checkpoint.
func acceptedRoots(checkpoints []string, keys Keyring) map[[32]byte]bool {
	roots := make(map[[32]byte]bool, len(checkpoints))
	for _, signed := range checkpoints {
		if cp, ok := verifyCheckpointSig(signed, keys); ok {
			roots[cp.Hash] = true
		}
	}
	return roots
}

// checkpointID renders a citable one-line checkpoint identity: origin, tree
// size, and the first 12 base64 chars of the RFC 6962 root.
func checkpointID(cp note.Checkpoint) string {
	root := base64.StdEncoding.EncodeToString(cp.Hash[:])
	if len(root) > 12 {
		root = root[:12]
	}
	return fmt.Sprintf("%s@%d root=%s…", cp.Origin, cp.Size, root)
}

// The hash-chain fold lives on sourceFold (foldChain): with no tombstones it is
// exactly chain.Verify; with tombstones it tolerates the seq gaps left by
// retention-deleted segments — a gap between two retained records is accepted
// only when it is fully covered by tombstoned ranges (the linking record is
// provably gone, not suppressed); any other break is still a chain error.

// interval is an inclusive seq range.
type interval struct{ lo, hi uint64 }

// mergeTombstoneRanges returns the tombstone seq ranges merged into disjoint,
// non-adjacent intervals sorted by start.
func mergeTombstoneRanges(tombstones []TombstoneInfo) []interval {
	ivs := make([]interval, 0, len(tombstones))
	for _, t := range tombstones {
		ivs = append(ivs, interval{t.SeqFirst, t.SeqLast})
	}
	sort.Slice(ivs, func(i, j int) bool { return ivs[i].lo < ivs[j].lo })
	var merged []interval
	for _, iv := range ivs {
		if n := len(merged); n > 0 && iv.lo <= merged[n-1].hi+1 {
			if iv.hi > merged[n-1].hi {
				merged[n-1].hi = iv.hi
			}
			continue
		}
		merged = append(merged, iv)
	}
	return merged
}

// rangeCovered reports whether [lo,hi] fits entirely within one merged interval.
func rangeCovered(merged []interval, lo, hi uint64) bool {
	for _, iv := range merged {
		if iv.lo <= lo && hi <= iv.hi {
			return true
		}
	}
	return false
}

// verifyAnchors cross-checks external timestamp receipts against the accepted
// checkpoints: a receipt matches only when the imprint stored in its DER token
// equals SHA-256 of an accepted, signature-valid checkpoint note AND the
// receipt's (origin, size, root) equals that checkpoint's (REQ-C-15). A receipt
// that matches nothing is surfaced as F-ANCHOR by buildFindings.
//
// A match proves imprint + nonce round-trip only; the TSA token's CMS signature
// is NOT verified in-process, so check.SignatureVerified stays false and the
// token remains externally verifiable via `openssl ts -verify` (REQ-C-15).
func verifyAnchors(checkpoints []string, receipts []anchor.Receipt, keys Keyring) AnchorCheck {
	check := AnchorCheck{Total: len(receipts), Configured: len(receipts) > 0}
	if len(receipts) == 0 {
		return check
	}

	// Index accepted checkpoints by the SHA-256 of their exact signed-note bytes
	// — the same imprint the anchor timestamped.
	byImprint := make(map[string]note.Checkpoint, len(checkpoints))
	for _, signed := range checkpoints {
		cp, ok := verifyCheckpointSig(signed, keys)
		if !ok {
			continue
		}
		sum := sha256.Sum256([]byte(signed))
		byImprint[hex.EncodeToString(sum[:])] = cp
	}

	for _, r := range receipts {
		imprint, _, genTime, err := anchor.ParseTokenImprint(r.Token)
		if err != nil {
			continue
		}
		cp, ok := byImprint[hex.EncodeToString(imprint)]
		if !ok {
			continue
		}
		if r.Origin != cp.Origin || r.Size != cp.Size ||
			r.RootB64 != base64.StdEncoding.EncodeToString(cp.Hash[:]) {
			continue
		}
		check.Matching++
		check.TSA = r.TSA
		check.Qualified = r.Qualified
		if genTime.After(check.LatestGenTime) {
			check.LatestGenTime = genTime
		}
	}
	return check
}

func verifyCheckpointSig(signed string, keys Keyring) (note.Checkpoint, bool) {
	for name, pub := range keys {
		text, err := note.Verify(signed, name, pub)
		if err != nil {
			continue
		}
		cp, err := note.ParseCheckpoint(text)
		if err != nil {
			return note.Checkpoint{}, false
		}
		return cp, true
	}
	return note.Checkpoint{}, false
}

type hbPayload struct {
	Health struct {
		ClockDriftMS int64 `json:"clock_drift_ms"`
	} `json:"health"`
}

type keyRevokedPayload struct {
	RevokedKeyID   string `json:"revoked_key_id"`
	RevokedKeyName string `json:"revoked_key_name"`
	Reason         string `json:"reason"`
	SuspectedSince string `json:"suspected_since"`
}

func buildFindings(sourceID string, res SourceResult, policy Policy) []evidence.Finding {
	var findings []evidence.Finding
	if !res.Chain.Valid {
		detail := "hash chain verification failed"
		if res.Chain.Err != nil {
			detail = res.Chain.Err.Error()
		}
		findings = append(findings, integrityFinding("F-CHAIN", "hash chain broken", detail))
	}
	if !res.Checkpoints.Consistent {
		findings = append(findings, integrityFinding("F-FORK", "checkpoint inconsistency",
			"a checkpoint is not an append-only extension of an earlier one (possible fork or rewrite)"))
	}
	if res.Checkpoints.Total > 0 && res.Checkpoints.SignaturesValid != res.Checkpoints.Total {
		findings = append(findings, integrityFinding("F-SIG", "invalid checkpoint signature",
			fmt.Sprintf("%d of %d checkpoints failed signature verification",
				res.Checkpoints.Total-res.Checkpoints.SignaturesValid, res.Checkpoints.Total)))
	}
	if res.Anchors.Total > 0 && res.Anchors.Matching != res.Anchors.Total {
		findings = append(findings, integrityFinding("F-ANCHOR",
			"Anchor receipt does not match any accepted checkpoint",
			fmt.Sprintf("%d of %d timestamp receipts do not bind to an accepted checkpoint "+
				"(imprint or origin/size/root mismatch)",
				res.Anchors.Total-res.Anchors.Matching, res.Anchors.Total)))
	}
	if res.Retention.ExpiredSegments > 0 && !res.Retention.RootsRetained {
		findings = append(findings, integrityFinding("F-RETENTION",
			"retention tombstone outside verifiable history",
			"a retention-deleted segment's Merkle root matches no accepted checkpoint; "+
				"the deletion cannot be tied to committed, signed history"))
	}
	for _, rev := range res.Revocations {
		since := rev.SuspectedSince
		if since == "" {
			since = "an unstated time"
		}
		findings = append(findings, evidence.Finding{
			ID:       "F-KEYREV",
			Severity: evidence.SeverityHigh,
			Title:    "signing key revoked on " + sourceID,
			Detail: fmt.Sprintf("key %s revoked at seq %d (reason: %s); events signed by it between %s and the revocation are suspect",
				keyRevLabel(rev), rev.Seq, reasonOrUnstated(rev.Reason), since),
			Recommendation: "correlate events in the exposure window against independent records and confirm the key was rotated",
		})
	}
	for i, w := range res.Continuity.Windows {
		if w.Bounded {
			continue
		}
		findings = append(findings, evidence.Finding{
			ID:       fmt.Sprintf("F-GAP-%d", i+1),
			Severity: evidence.SeverityMedium,
			Title:    "unobserved window on " + sourceID,
			Detail: fmt.Sprintf("no heartbeat for %s (%s to %s); activity in that window is unprovable",
				w.Duration.Round(time.Second), envelope.FormatTime(w.Start), envelope.FormatTime(w.End)),
			Recommendation: "enable agent auto-start at boot and correlate with host records",
		})
	}
	if res.MaxClockDriftMS > policy.MaxClockDriftMS {
		findings = append(findings, evidence.Finding{
			ID:       "F-CLOCK",
			Severity: evidence.SeverityLow,
			Title:    "clock drift over policy on " + sourceID,
			Detail:   fmt.Sprintf("max observed drift %dms exceeds policy %dms", res.MaxClockDriftMS, policy.MaxClockDriftMS),
		})
	}
	return findings
}

// keyRevLabel renders the revoked key as its id, falling back to the key name
// when the payload carried no id.
func keyRevLabel(rev KeyRevocation) string {
	if rev.RevokedKeyID != "" {
		return rev.RevokedKeyID
	}
	if rev.RevokedKeyName != "" {
		return rev.RevokedKeyName
	}
	return "unknown"
}

func reasonOrUnstated(reason string) string {
	if reason == "" {
		return "unstated"
	}
	return reason
}

func integrityFinding(id, title, detail string) evidence.Finding {
	return evidence.Finding{ID: id, Severity: evidence.SeverityHigh, Title: title, Detail: detail}
}
