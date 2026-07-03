package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/arhuman/prooflog/internal/api"
)

// runHold manages legal holds on the store: place, release, or list. Holds
// exempt a source (or seq range) from retention deletion until released (WS6).
func runHold(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: prooflog hold <place|release|list> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "place":
		return runHoldPlace(rest)
	case "release":
		return runHoldRelease(rest)
	case "list":
		return runHoldList(rest)
	default:
		return fmt.Errorf("unknown hold subcommand %q (want place|release|list)", sub)
	}
}

func runHoldPlace(args []string) error {
	fs := flag.NewFlagSet("hold place", flag.ContinueOnError)
	storeAddr := fs.String("store-addr", "127.0.0.1:9700", "store gRPC address")
	source := fs.String("source", "", "source id to hold (required)")
	fromSeq := fs.Uint64("from-seq", 0, "first seq of the held range (with --to-seq)")
	toSeq := fs.Uint64("to-seq", 0, "last seq of the held range (with --from-seq)")
	reason := fs.String("reason", "", "reason for the hold (required)")
	placedBy := fs.String("placed-by", "", "who placed the hold")
	tls := tlsFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" {
		return fmt.Errorf("--source is required")
	}
	if *reason == "" {
		return fmt.Errorf("--reason is required")
	}
	hasRange := *fromSeq != 0 || *toSeq != 0
	if hasRange && (*fromSeq == 0 || *toSeq == 0 || *fromSeq > *toSeq) {
		return fmt.Errorf("--from-seq and --to-seq must both be set with from <= to")
	}

	client, cleanup, err := storeClient(*storeAddr, tls)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h, err := client.PlaceHold(ctx, &api.PlaceHoldRequest{
		SourceId: *source, SeqFirst: *fromSeq, SeqLast: *toSeq,
		HasRange: hasRange, Reason: *reason, PlacedBy: *placedBy,
	})
	if err != nil {
		return fmt.Errorf("place hold: %w", err)
	}
	fmt.Printf("hold placed: %s on %s%s (reason: %s)\n", h.HoldId, h.SourceId, holdRange(h), h.Reason)
	return nil
}

func runHoldRelease(args []string) error {
	fs := flag.NewFlagSet("hold release", flag.ContinueOnError)
	storeAddr := fs.String("store-addr", "127.0.0.1:9700", "store gRPC address")
	id := fs.String("id", "", "hold id to release (required)")
	tls := tlsFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	client, cleanup, err := storeClient(*storeAddr, tls)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h, err := client.ReleaseHold(ctx, &api.ReleaseHoldRequest{HoldId: *id})
	if err != nil {
		return fmt.Errorf("release hold: %w", err)
	}
	fmt.Printf("hold released: %s on %s (released_at %s)\n", h.HoldId, h.SourceId, h.ReleasedAt)
	return nil
}

func runHoldList(args []string) error {
	fs := flag.NewFlagSet("hold list", flag.ContinueOnError)
	storeAddr := fs.String("store-addr", "127.0.0.1:9700", "store gRPC address")
	source := fs.String("source", "", "filter to one source (default: all)")
	tls := tlsFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, cleanup, err := storeClient(*storeAddr, tls)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pageToken := ""
	printed := 0
	for {
		resp, err := client.ListHolds(ctx, &api.ListHoldsRequest{SourceId: *source, PageToken: pageToken})
		if err != nil {
			return fmt.Errorf("list holds: %w", err)
		}
		for _, h := range resp.Holds {
			state := "active"
			if h.ReleasedAt != "" {
				state = "released " + h.ReleasedAt
			}
			fmt.Printf("%s  %s%s  [%s]  reason: %s\n", h.HoldId, h.SourceId, holdRange(h), state, h.Reason)
			printed++
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	if printed == 0 {
		fmt.Println("no holds")
	}
	return nil
}

// holdRange renders a hold's seq range, or "" for a whole-source hold.
func holdRange(h *api.Hold) string {
	if !h.HasRange {
		return " (whole source)"
	}
	return fmt.Sprintf(" seq %d-%d", h.SeqFirst, h.SeqLast)
}

// storeClient dials the store and returns a client plus a cleanup func.
func storeClient(addr string, tls *api.TLSConfig) (api.StoreServiceClient, func(), error) {
	cfg := api.TLSConfig{}
	if tls != nil {
		cfg = *tls
	}
	if cfg.Insecure {
		warnInsecure("store client")
	}
	cc, err := api.Dial(addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	return api.NewStoreClient(cc), func() { _ = cc.Close() }, nil
}
