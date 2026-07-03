package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/arhuman/prooflog/internal/agent"
)

// runAgent runs the local agent daemon: HTTP ingest, spool, sealing, upload,
// and heartbeats (REQ-E-04, REQ-E-06).
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	configPath := fs.String("config", "config.json", "path to the agent config")
	unsafeBind := fs.Bool("unsafe-bind", false, "allow a non-loopback ingest bind address (local-only by design; never production)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		return err
	}

	a, err := agent.New(cfg, nil)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a.Start(ctx)

	errCh := make(chan error, 1)
	go func() { errCh <- a.Serve(ctx, cfg.HTTPAddr, *unsafeBind) }()

	fmt.Fprintf(os.Stderr, "prooflog agent running for %s (ingest %s, store %s)\n",
		cfg.SourceID, cfg.HTTPAddr, cfg.StoreAddr)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			a.Stop()
			return fmt.Errorf("http server: %w", err)
		}
	}
	a.Stop()
	return nil
}
