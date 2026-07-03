package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
)

// drainTimeout bounds graceful shutdown: after a signal, in-flight RPCs get this
// long to finish before the server is force-stopped, so shutdown cannot hang
// forever on a stuck stream.
const drainTimeout = 10 * time.Second

// grpcDaemon is one assembled gRPC service ready to serve: a bound listener, the
// configured server, an optional background loop (retention, verification,
// anchoring) bound to the shutdown context, and a one-line startup banner.
type grpcDaemon struct {
	server     *grpc.Server
	listener   net.Listener
	background func(ctx context.Context)
	banner     string
}

// serveGRPC runs a gRPC daemon until SIGINT/SIGTERM, then drains within
// drainTimeout before force-stopping. It is the single lifecycle shared by the
// store and verifier daemons: signal → background loops → serve → bounded drain.
func serveGRPC(d grpcDaemon) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if d.background != nil {
		go d.background(ctx)
	}
	go func() {
		<-ctx.Done()
		drainGRPC(d.server)
	}()

	if d.banner != "" {
		fmt.Fprintln(os.Stderr, d.banner)
	}
	if err := d.server.Serve(d.listener); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// drainGRPC attempts a graceful stop, falling back to a hard stop if in-flight
// RPCs do not finish within drainTimeout.
func drainGRPC(srv *grpc.Server) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drainTimeout):
		srv.Stop()
	}
}

// listenTCP binds a TCP listener, wrapping the error consistently across daemons.
func listenTCP(addr string) (net.Listener, error) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	return ln, nil
}
