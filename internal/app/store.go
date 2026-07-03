// Package app is the composition root: it assembles the daemons' runtime
// components from plain config structs, so the wiring — TLS, privileged-RPC
// gating, event sinks — is unit-testable without driving a flag.FlagSet. The
// cmd/ layer is a thin translation of CLI flags into these structs (REQ-E-04).
package app

import (
	"log/slog"
	"time"

	"google.golang.org/grpc"

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/store"
)

// StoreConfig is the resolved store-daemon configuration, translated from CLI
// flags into plain values so assembly is testable without a FlagSet.
type StoreConfig struct {
	DBPath          string
	BlobDir         string
	Retention       time.Duration
	Policy          store.RetentionPolicy
	AgentHTTP       string
	TLS             api.TLSConfig
	AllowUnauth     bool
	RequireReadAuth bool
	Logger          *slog.Logger
}

// StoreServer is an assembled, not-yet-listening store service: the gRPC server
// and the opened store (the caller owns Store.Close and drives Server via the
// cmd/ serve harness), plus the human-facing auth warnings to print before
// serving.
type StoreServer struct {
	Server   *grpc.Server
	Store    *store.Store
	Warnings []string
}

// NewStoreServer opens the store and assembles its gRPC server with the
// privileged-RPC gate implied by the auth config. It performs no I/O beyond
// opening the store, so the gating decision and warnings are unit-testable via
// StoreAuthWarnings. On any assembly failure the store is closed before return.
func NewStoreServer(cfg StoreConfig) (*StoreServer, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	st, err := store.Open(store.Config{
		DBPath:    cfg.DBPath,
		BlobDir:   cfg.BlobDir,
		Retention: cfg.Retention,
		Policy:    cfg.Policy,
		Logger:    logger,
	})
	if err != nil {
		return nil, err
	}
	st.SetEventSink(store.NewAgentEventSink(cfg.AgentHTTP, logger))

	srv, err := api.NewServer(cfg.TLS, api.RequireMTLS(cfg.AllowUnauth, storePrivilege(cfg.RequireReadAuth))...)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	api.RegisterStore(srv, st)

	return &StoreServer{Server: srv, Store: st, Warnings: StoreAuthWarnings(cfg)}, nil
}

// storePrivilege resolves which methods count as privileged (and thus require
// mTLS when auth is enforced): mutations always, plus reads when RequireReadAuth
// is set so the offline verifier can pull without a client cert by default.
func storePrivilege(requireReadAuth bool) api.Privileged {
	if requireReadAuth {
		return func(m string) bool { return api.StorePrivileged(m) || api.StoreReadPrivileged(m) }
	}
	return api.StorePrivileged
}

// StoreAuthWarnings returns the human-facing warnings describing how the store
// will (or won't) authenticate callers, given the resolved auth config. It is a
// pure function of the auth flags, so the full gating matrix is unit-testable.
// The order matches the historical CLI output: mutation gate, then read gate.
func StoreAuthWarnings(cfg StoreConfig) []string {
	var w []string
	switch {
	case cfg.AllowUnauth:
		w = append(w,
			"store: legal-hold place/release RPCs accept ANY caller that can reach the socket (explicitly allowed via --allow-unauthenticated)",
			"store: segment upload and checkpoint RPCs accept ANY caller that can reach the socket (explicitly allowed via --allow-unauthenticated)")
	case cfg.TLS.Insecure || !cfg.TLS.ClientAuth:
		w = append(w,
			"store: legal-hold place/release RPCs will be DENIED because the store cannot authenticate callers; enable --tls-client-auth (mTLS), or pass --allow-unauthenticated for local demos",
			"store: segment upload and checkpoint RPCs will be DENIED because the store cannot authenticate callers; enable --tls-client-auth (mTLS), or pass --allow-unauthenticated for local demos")
	}
	switch {
	case cfg.AllowUnauth:
		w = append(w, "store: read RPCs (segment pull, hold/tombstone list) are OPEN to any caller (unauthenticated access explicitly allowed)")
	case cfg.RequireReadAuth:
		w = append(w, "store: read RPCs (segment pull, hold/tombstone list) are GATED on mTLS client auth (--require-read-auth)")
	default:
		w = append(w, "store: read RPCs (segment pull, hold/tombstone list) are OPEN to any caller; pass --require-read-auth to gate them on mTLS")
	}
	return w
}
