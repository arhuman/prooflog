package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/verifier"
	"github.com/arhuman/prooflog/internal/verifierd"
)

// runVerifier runs the verifier trust-anchor daemon: it accepts checkpoints over
// gRPC (enforcing the append-only rule at submission), and periodically pulls
// segments from the store to run the full offline engine (REQ-C-02, REQ-C-07,
// REQ-E-05).
func runVerifier(args []string) error {
	fs := flag.NewFlagSet("verifier", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:9800", "gRPC listen address")
	storeAddr := fs.String("store-addr", "127.0.0.1:9700", "store address to pull segments from ('' disables pull)")
	dataDir := fs.String("data-dir", "verifier-data", "directory for persisted checkpoints")
	keysPath := fs.String("keys", "verifier-keys.json", "registered source keys JSON")
	interval := fs.Duration("interval", time.Minute, "pull-and-verify cycle interval")
	locality := fs.String("locality", "", "operator-declared verifier jurisdiction (e.g. EU/DE); recorded, not proven")
	tsaURL := fs.String("tsa-url", "", "RFC 3161 TSA URL to anchor checkpoints ('' disables anchoring)")
	tsaQualified := fs.Bool("tsa-qualified", false, "operator declares the TSA eIDAS-qualified (Art. 41)")
	anchorInterval := fs.Duration("anchor-interval", time.Hour, "checkpoint anchoring interval (with --tsa-url)")
	anchorsDir := fs.String("anchors-dir", "", "directory for anchor receipts (default: <data-dir>/anchors)")
	tls := tlsFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	reg, err := verifier.LoadRegistry(*keysPath)
	if err != nil {
		return err
	}

	var storeClient api.StoreServiceClient
	if *storeAddr != "" {
		cc, err := api.Dial(*storeAddr, *tls)
		if err != nil {
			return err
		}
		defer cc.Close()
		storeClient = api.NewStoreClient(cc)
	}

	var anchorImpl anchor.Anchor
	if *tsaURL != "" {
		anchorImpl = &anchor.TSAClient{URL: *tsaURL, Qualified: *tsaQualified}
	}

	daemon, err := verifierd.NewDaemon(verifierd.DaemonConfig{
		Registry:       reg,
		DataDir:        *dataDir,
		Store:          storeClient,
		Policy:         verifier.DefaultPolicy(),
		Anchor:         anchorImpl,
		AnchorInterval: *anchorInterval,
		AnchorsDir:     *anchorsDir,
	})
	if err != nil {
		return err
	}

	srv, err := api.NewServer(*tls)
	if err != nil {
		return err
	}
	api.RegisterVerifier(srv, daemon)

	ln, err := listenTCP(*listen)
	if err != nil {
		return err
	}

	if *locality != "" {
		fmt.Fprintf(os.Stderr, "verifier: locality declared: %s\n", *locality)
	}
	if tls.Insecure {
		warnInsecure("verifier")
	}
	if anchorImpl != nil {
		fmt.Fprintf(os.Stderr, "verifier: anchoring checkpoints via %s (qualified=%v)\n", anchorImpl.Name(), *tsaQualified)
	}
	return serveGRPC(grpcDaemon{
		server:   srv,
		listener: ln,
		background: func(ctx context.Context) {
			if storeClient != nil {
				go daemon.StartVerificationLoop(ctx, *interval)
			}
			if anchorImpl != nil {
				go daemon.StartAnchorLoop(ctx)
			}
		},
		banner: fmt.Sprintf("prooflog verifier listening on %s (store=%s data=%s)", *listen, *storeAddr, *dataDir),
	})
}
