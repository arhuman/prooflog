package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/spool"
	"github.com/arhuman/prooflog/internal/verifier"
)

const maxPullFrames = 1 << 20

// verifyOpts selects the record source, checkpoints, and registered keys for an
// offline verification run shared by `verify` and `report`.
type verifyOpts struct {
	spoolDir          string
	storeAddr         string
	sourceID          string
	checkpointsDir    string
	anchorsDir        string
	keysPath          string
	heartbeatInterval time.Duration
	tls               *api.TLSConfig
}

// gatherResult assembles a source (records + checkpoints + keyring) and runs the
// offline verification engine, returning the result and resolved source id
// (REQ-C-02, REQ-E-05).
func gatherResult(ctx context.Context, o verifyOpts) (verifier.SourceResult, string, error) {
	entries, sourceID, err := gatherEntries(ctx, o)
	if err != nil {
		return verifier.SourceResult{}, "", err
	}
	if o.sourceID != "" {
		sourceID = o.sourceID
	}
	if sourceID == "" {
		return verifier.SourceResult{}, "", fmt.Errorf("could not resolve source id (use --source)")
	}

	var checkpoints []string
	if o.checkpointsDir != "" {
		checkpoints, err = verifier.LoadCheckpoints(o.checkpointsDir, sourceID)
		if err != nil {
			return verifier.SourceResult{}, "", err
		}
	}

	var anchors []anchor.Receipt
	if o.anchorsDir != "" {
		anchors, err = anchor.LoadReceipts(o.anchorsDir, sourceID)
		if err != nil {
			return verifier.SourceResult{}, "", err
		}
	}

	keyring := verifier.Keyring{}
	origin := ""
	if o.keysPath != "" {
		reg, err := verifier.LoadRegistry(o.keysPath)
		if err != nil {
			return verifier.SourceResult{}, "", err
		}
		if kr, ok := reg.Keyring(sourceID); ok {
			keyring = kr
		}
		if sk, ok := reg.Source(sourceID); ok {
			origin = sk.Origin
		}
	}

	policy := verifier.DefaultPolicy()
	if o.heartbeatInterval > 0 {
		policy.HeartbeatInterval = o.heartbeatInterval
	}
	src := verifier.Source{SourceID: sourceID, Origin: origin, Entries: entries, Checkpoints: checkpoints, Anchors: anchors}
	return verifier.Verify(src, keyring, policy), sourceID, nil
}

func gatherEntries(ctx context.Context, o verifyOpts) ([]chain.Entry, string, error) {
	switch {
	case o.spoolDir != "":
		return spoolEntries(o.spoolDir)
	case o.storeAddr != "":
		if o.sourceID == "" {
			return nil, "", fmt.Errorf("--source is required with --store-addr")
		}
		entries, err := pullEntries(ctx, o.storeAddr, o.sourceID, o.tls)
		return entries, o.sourceID, err
	default:
		return nil, "", fmt.Errorf("provide --spool <dir> or --store-addr <addr>")
	}
}

func spoolEntries(dir string) ([]chain.Entry, string, error) {
	sp, err := spool.Open(spool.Config{Dir: dir})
	if err != nil {
		return nil, "", err
	}
	defer sp.Close()
	it, err := sp.Iter(0)
	if err != nil {
		return nil, "", err
	}
	defer it.Close()
	var entries []chain.Entry
	var sourceID string
	for {
		rec, ok, err := it.Next()
		if err != nil {
			return nil, "", err
		}
		if !ok {
			break
		}
		if sourceID == "" {
			sourceID = rec.SourceID
		}
		entries = append(entries, chain.Entry{Bytes: rec.Bytes(), Hash: rec.HashHex()})
	}
	return entries, sourceID, nil
}

func pullEntries(ctx context.Context, addr, sourceID string, tls *api.TLSConfig) ([]chain.Entry, error) {
	cfg := api.TLSConfig{}
	if tls != nil {
		cfg = *tls
	}
	if cfg.Insecure {
		warnInsecure("store client")
	}
	cc, err := api.Dial(addr, cfg)
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	stream, err := api.NewStoreClient(cc).PullSegments(ctx, &api.PullRequest{SourceId: sourceID, FromSeq: 1})
	if err != nil {
		return nil, fmt.Errorf("pull: %w", err)
	}
	var entries []chain.Entry
	for {
		fr, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("pull recv: %w", err)
		}
		if len(entries) >= maxPullFrames {
			return nil, fmt.Errorf("pull exceeds %d frames", maxPullFrames)
		}
		entries = append(entries, chain.Entry{Bytes: fr.RecordBytes, Hash: hex.EncodeToString(fr.RecordHash)})
	}
	return entries, nil
}

// parsePeriod parses "YYYY-MM-DD:YYYY-MM-DD" into a UTC start and end.
func parsePeriod(s string) (start, end time.Time, err error) {
	if s == "" {
		return time.Time{}, time.Time{}, nil
	}
	from, to, ok := strings.Cut(s, ":")
	if !ok {
		return time.Time{}, time.Time{}, fmt.Errorf("period must be YYYY-MM-DD:YYYY-MM-DD")
	}
	start, err = time.Parse("2006-01-02", from)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("period start: %w", err)
	}
	end, err = time.Parse("2006-01-02", to)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("period end: %w", err)
	}
	return start.UTC(), end.UTC(), nil
}
