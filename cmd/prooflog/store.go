package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/arhuman/prooflog/internal/app"
	"github.com/arhuman/prooflog/internal/store"
)

// runStore runs the central store service: SQLite index over a blob directory,
// exposed as the gRPC StoreService (REQ-E-04).
func runStore(args []string) error {
	fs := flag.NewFlagSet("store", flag.ContinueOnError)
	dir := fs.String("dir", "store-data", "base directory for the index and blobs")
	dbPath := fs.String("db", "", "SQLite index path (default: <dir>/store.db)")
	blobDir := fs.String("blob-dir", "", "segment blob directory (default: <dir>/blobs)")
	listen := fs.String("listen", "127.0.0.1:9700", "gRPC listen address")
	retention := fs.Duration("retention", 365*24*time.Hour, "retention shorthand; synthesizes {default_days} when --retention-policy is unset")
	retentionPolicy := fs.String("retention-policy", "", "JSON retention policy file {\"default_days\":N,\"frameworks\":{...}}; only default_days drives deletion in v1, frameworks are recorded/reported only")
	checkInterval := fs.Duration("retention-check-interval", 24*time.Hour, "how often to enforce retention (also runs once at startup)")
	agentHTTP := fs.String("agent-http", "", "designated agent HTTP ingest addr (host:port) that seals retention/hold events into the chain; when unset, actions still take effect but events are not chain-sealed")
	locality := fs.String("locality", "", "operator-declared store jurisdiction (e.g. CH); recorded, not proven")
	allowUnauthenticated := fs.Bool("allow-unauthenticated", false, "allow privileged RPCs (segment upload, checkpoint, legal-hold place/release) without mTLS client auth (demo/loopback only)")
	allowUnauthHolds := fs.Bool("allow-unauthenticated-holds", false, "alias for --allow-unauthenticated (kept for compatibility)")
	requireReadAuth := fs.Bool("require-read-auth", false, "also gate read RPCs (segment pull, hold/tombstone list) on mTLS client auth; off by default so the offline verifier can pull without a client cert")
	tls := tlsFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbPath == "" {
		*dbPath = filepath.Join(*dir, "store.db")
	}
	if *blobDir == "" {
		*blobDir = filepath.Join(*dir, "blobs")
	}

	policy, err := loadRetentionPolicy(*retentionPolicy, *retention)
	if err != nil {
		return err
	}

	// Either auth flag opts privileged RPCs out of the mTLS requirement.
	ss, err := app.NewStoreServer(app.StoreConfig{
		DBPath:          *dbPath,
		BlobDir:         *blobDir,
		Retention:       *retention,
		Policy:          policy,
		AgentHTTP:       *agentHTTP,
		TLS:             *tls,
		AllowUnauth:     *allowUnauthenticated || *allowUnauthHolds,
		RequireReadAuth: *requireReadAuth,
		Logger:          slog.Default(),
	})
	if err != nil {
		return err
	}
	defer ss.Store.Close()

	ln, err := listenTCP(*listen)
	if err != nil {
		return err
	}

	if *locality != "" {
		fmt.Fprintf(os.Stderr, "store: locality declared: %s\n", *locality)
	}
	if tls.Insecure {
		warnInsecure("store")
	}
	for _, w := range ss.Warnings {
		fmt.Fprintln(os.Stderr, w)
	}
	// Record any policy change, then run retention enforcement at startup and on a
	// ticker. Both seal system events through the designated agent (graceful
	// degradation when --agent-http is unset).
	return serveGRPC(grpcDaemon{
		server:     ss.Server,
		listener:   ln,
		background: func(ctx context.Context) { ss.Store.RunRetention(ctx, *checkInterval) },
		banner:     fmt.Sprintf("prooflog store listening on %s (db=%s blobs=%s)", *listen, *dbPath, *blobDir),
	})
}

// loadRetentionPolicy reads a JSON policy file, or synthesizes {default_days}
// from the --retention duration shorthand when no file is given.
func loadRetentionPolicy(path string, retention time.Duration) (store.RetentionPolicy, error) {
	if path == "" {
		return store.RetentionPolicy{DefaultDays: int(retention.Hours() / 24)}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return store.RetentionPolicy{}, fmt.Errorf("read retention policy: %w", err)
	}
	var p store.RetentionPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return store.RetentionPolicy{}, fmt.Errorf("parse retention policy: %w", err)
	}
	return p, nil
}
