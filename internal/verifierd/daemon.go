// Package verifierd is the gRPC transport layer around the offline verification
// engine in package verifier: it accepts checkpoints over gRPC, enforces the
// append-only commitment at submission time, and periodically pulls segments
// from the store to drive the pure engine (REQ-C-02, REQ-C-07, REQ-E-05).
// Keeping the daemon here — not in package verifier — lets consumers of the
// engine's value types (report, export) stay free of any grpc/api import.
package verifierd

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/note"
	"github.com/arhuman/prooflog/internal/verifier"
)

// defaultAnchorInterval bounds TSA cost when anchoring is enabled but no
// interval is configured.
const defaultAnchorInterval = time.Hour

// Daemon is the verifier trust anchor: it accepts checkpoints over gRPC,
// enforces the append-only commitment at submission time, and periodically pulls
// segments from the store to run the full offline engine (REQ-C-02, REQ-C-07,
// REQ-E-05). It is transport-facing; the engine functions stay pure.
type Daemon struct {
	api.UnimplementedVerifierServiceServer

	reg    *verifier.Registry
	cps    *verifier.CheckpointStore
	store  api.StoreServiceClient
	policy verifier.Policy
	log    *slog.Logger

	anchor         anchor.Anchor
	anchorLog      *anchor.Log
	anchorInterval time.Duration

	mu      sync.Mutex
	results map[string]verifier.SourceResult
}

// DaemonConfig configures a Daemon.
type DaemonConfig struct {
	Registry *verifier.Registry
	DataDir  string
	// Store is the store client used for periodic pull-and-verify; may be nil to
	// run submission-only (no pull cycle).
	Store  api.StoreServiceClient
	Policy verifier.Policy
	Logger *slog.Logger

	// Anchor externally timestamps advancing checkpoint heads; nil disables
	// anchoring (REQ-C-15). AnchorInterval bounds TSA cost (default 1h).
	// AnchorsDir stores the receipt JSONL files; empty puts them under DataDir.
	Anchor         anchor.Anchor
	AnchorInterval time.Duration
	AnchorsDir     string
}

// NewDaemon opens the checkpoint store and builds a Daemon (REQ-C-07).
func NewDaemon(cfg DaemonConfig) (*Daemon, error) {
	if cfg.Registry == nil {
		return nil, fmt.Errorf("verifier: daemon requires a registry")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Policy == (verifier.Policy{}) {
		cfg.Policy = verifier.DefaultPolicy()
	}
	cps, err := verifier.OpenCheckpointStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		reg:     cfg.Registry,
		cps:     cps,
		store:   cfg.Store,
		policy:  cfg.Policy,
		log:     cfg.Logger,
		results: make(map[string]verifier.SourceResult),
	}
	if cfg.Anchor != nil {
		dir := cfg.AnchorsDir
		if dir == "" {
			dir = filepath.Join(cfg.DataDir, "anchors")
		}
		al, err := anchor.OpenAnchorLog(dir)
		if err != nil {
			return nil, err
		}
		d.anchor = cfg.Anchor
		d.anchorLog = al
		d.anchorInterval = cfg.AnchorInterval
		if d.anchorInterval <= 0 {
			d.anchorInterval = defaultAnchorInterval
		}
	}
	return d, nil
}

// SubmitCheckpoint verifies a checkpoint's signature against the source's
// registered key and enforces the append-only rule before persisting it. Forks
// are rejected with codes.FailedPrecondition — the anti-rewrite mechanism
// (REQ-C-06, REQ-C-07).
func (d *Daemon) SubmitCheckpoint(_ context.Context, n *api.SignedNote) (*api.CheckpointAck, error) {
	sourceKeys := d.reg.SourceKeys(n.SourceId)
	if len(sourceKeys) == 0 {
		return nil, status.Errorf(codes.PermissionDenied, "verifier: unregistered source %q", n.SourceId)
	}
	// Try every registered key: after a rotation the source has more than one,
	// and a submitted checkpoint may be signed by either the old or new key.
	var text string
	var verifyErr error
	for _, sk := range sourceKeys {
		text, verifyErr = note.Verify(n.Note, sk.KeyName, sk.PublicKey)
		if verifyErr == nil {
			break
		}
	}
	if verifyErr != nil {
		return nil, status.Errorf(codes.Unauthenticated, "verifier: signature: %v", verifyErr)
	}
	cp, err := note.ParseCheckpoint(text)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "verifier: checkpoint: %v", err)
	}
	if err := d.cps.Accept(n.SourceId, n.Note, cp); err != nil {
		d.log.Warn("checkpoint rejected", "source", n.SourceId, "err", err)
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	d.log.Info("checkpoint accepted", "source", n.SourceId, "size", cp.Size)
	return &api.CheckpointAck{Accepted: true}, nil
}

// RunVerification runs one pull-and-verify cycle over every registered source,
// caching the results for reporting (REQ-C-02, REQ-E-05). It is a no-op without
// a store client.
func (d *Daemon) RunVerification(ctx context.Context) error {
	if d.store == nil {
		return nil
	}
	for _, sourceID := range d.reg.SourceIDs() {
		res, err := d.verifySource(ctx, sourceID)
		if err != nil {
			d.log.Error("verify source failed", "source", sourceID, "err", err)
			continue
		}
		d.mu.Lock()
		d.results[sourceID] = res
		d.mu.Unlock()
		d.log.Info("source verified", "source", sourceID,
			"seq_last", res.SeqLast, "chain_valid", res.Chain.Valid,
			"checkpoints_consistent", res.Checkpoints.Consistent, "findings", len(res.Findings))
	}
	return nil
}

func (d *Daemon) verifySource(ctx context.Context, sourceID string) (verifier.SourceResult, error) {
	checkpoints, err := d.cps.All(sourceID)
	if err != nil {
		return verifier.SourceResult{}, err
	}
	var receipts []anchor.Receipt
	if d.anchorLog != nil {
		if receipts, err = d.anchorLog.All(sourceID); err != nil {
			return verifier.SourceResult{}, err
		}
	}
	tombstones, err := d.pullTombstones(ctx, sourceID)
	if err != nil {
		return verifier.SourceResult{}, err
	}
	origin := ""
	if sk, ok := d.reg.Source(sourceID); ok {
		origin = sk.Origin
	}
	keyring, _ := d.reg.Keyring(sourceID)

	// Drive the pull stream one frame at a time into the same engine Verify uses
	// (see verifier.StreamVerifier): the result is identical to Verify over the
	// full slice, but no frame is retained, so memory is O(1) in the raw frames
	// instead of O(n).
	src := verifier.Source{
		SourceID:    sourceID,
		Origin:      origin,
		Checkpoints: checkpoints,
		Anchors:     receipts,
		Tombstones:  tombstones,
	}
	sv := verifier.NewStreamVerifier(src, keyring, d.policy)
	if err := d.streamInto(ctx, sourceID, sv); err != nil {
		return verifier.SourceResult{}, err
	}
	return sv.Result(), nil
}

// pullTombstones fetches the source's retention tombstones from the store so the
// engine can exempt deleted ranges from gap findings (WS6). It is a no-op
// without a store client.
func (d *Daemon) pullTombstones(ctx context.Context, sourceID string) ([]verifier.TombstoneInfo, error) {
	if d.store == nil {
		return nil, nil
	}
	var out []verifier.TombstoneInfo
	pageToken := ""
	for {
		resp, err := d.store.ListTombstones(ctx, &api.ListTombstonesRequest{
			SourceId: sourceID, PageToken: pageToken,
		})
		if err != nil {
			return nil, fmt.Errorf("verifier: list tombstones %s: %w", sourceID, err)
		}
		for _, t := range resp.Tombstones {
			out = append(out, verifier.TombstoneInfo{
				SegmentID: t.SegmentId, SeqFirst: t.SeqFirst, SeqLast: t.SeqLast,
				Root: t.Root, Policy: t.Policy,
			})
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return out, nil
}

// RunAnchoring stamps each source's current checkpoint head against the TSA when
// it has advanced past the last anchored receipt, appending the receipt to the
// anchor Log. It stamps at most one checkpoint per source per call — time-based
// batching bounds TSA cost regardless of checkpoint rate (REQ-C-15). Failures
// are logged and skipped; anchoring is additive and never blocks verification.
func (d *Daemon) RunAnchoring(ctx context.Context) error {
	if d.anchor == nil {
		return nil
	}
	for _, sourceID := range d.reg.SourceIDs() {
		notes, err := d.cps.All(sourceID)
		if err != nil {
			d.log.Error("anchor: read checkpoints failed", "source", sourceID, "err", err)
			continue
		}
		if len(notes) == 0 {
			continue
		}
		latest := notes[len(notes)-1]
		cp, err := verifier.CheckpointOf(latest)
		if err != nil {
			d.log.Error("anchor: parse checkpoint failed", "source", sourceID, "err", err)
			continue
		}
		receipts, err := d.anchorLog.All(sourceID)
		if err != nil {
			d.log.Error("anchor: read receipts failed", "source", sourceID, "err", err)
			continue
		}
		var lastAnchored uint64
		for _, r := range receipts {
			if r.Size > lastAnchored {
				lastAnchored = r.Size
			}
		}
		if cp.Size <= lastAnchored {
			continue // head has not advanced since the last stamp
		}
		rec, err := d.anchor.Anchor(ctx, []byte(latest))
		if err != nil {
			d.log.Error("anchor: TSA failed", "source", sourceID, "size", cp.Size, "err", err)
			continue
		}
		if err := d.anchorLog.Append(sourceID, rec); err != nil {
			d.log.Error("anchor: append receipt failed", "source", sourceID, "err", err)
			continue
		}
		d.log.Info("checkpoint anchored", "source", sourceID, "size", cp.Size,
			"tsa", rec.TSA, "gen_time", rec.GenTime)
	}
	return nil
}

// StartAnchorLoop runs RunAnchoring at the configured interval until ctx is
// cancelled. It is a no-op when anchoring is disabled.
func (d *Daemon) StartAnchorLoop(ctx context.Context) {
	if d.anchor == nil {
		return
	}
	if err := d.RunAnchoring(ctx); err != nil {
		d.log.Error("initial anchoring failed", "err", err)
	}
	t := time.NewTicker(d.anchorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.RunAnchoring(ctx); err != nil {
				d.log.Error("anchor cycle failed", "err", err)
			}
		}
	}
}

// streamInto pulls a source's frames from genesis and folds each one on arrival,
// retaining none. Verification stays a full pass from seq 1 every cycle, so the
// unbounded buffer and the maxPull hard error that failed sources past ~1M frames
// are both gone: memory is O(1) in the frames, bounded per-frame by the gRPC
// receive limit (P3).
//
// The pass runs from genesis, not from a persisted lastVerifiedSeq+1, on purpose:
// tombstones and legal holds are dynamic. A tombstone (or hold) recorded in a
// later cycle can retroactively exempt a chain gap emitted in an earlier one —
// verifyRetention and foldChain only reproduce that exemption by re-scanning the
// whole source with the current tombstone set. An incremental skip that trusted a
// cached cursor would keep emitting the stale gap, so it is deliberately not done.
func (d *Daemon) streamInto(ctx context.Context, sourceID string, sv *verifier.StreamVerifier) error {
	stream, err := d.store.PullSegments(ctx, &api.PullRequest{SourceId: sourceID, FromSeq: 1})
	if err != nil {
		return fmt.Errorf("verifier: pull %s: %w", sourceID, err)
	}
	for {
		fr, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("verifier: pull recv: %w", err)
		}
		sv.Add(chain.Entry{Bytes: fr.RecordBytes, Hash: hex.EncodeToString(fr.RecordHash)})
	}
	return nil
}

// StartVerificationLoop runs RunVerification at interval until ctx is cancelled.
func (d *Daemon) StartVerificationLoop(ctx context.Context, interval time.Duration) {
	if err := d.RunVerification(ctx); err != nil {
		d.log.Error("initial verification failed", "err", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.RunVerification(ctx); err != nil {
				d.log.Error("verification cycle failed", "err", err)
			}
		}
	}
}

// Results returns a snapshot of the latest per-source verification results.
func (d *Daemon) Results() map[string]verifier.SourceResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]verifier.SourceResult, len(d.results))
	for k, v := range d.results {
		out[k] = v
	}
	return out
}
