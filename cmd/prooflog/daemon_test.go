package main

import (
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestListenTCPBindsAndErrors(t *testing.T) {
	ln, err := listenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenTCP: %v", err)
	}
	defer ln.Close()
	if ln.Addr().Network() != "tcp" {
		t.Fatalf("network = %q, want tcp", ln.Addr().Network())
	}
	if _, err := listenTCP("127.0.0.1:99999"); err == nil {
		t.Fatal("listenTCP on an out-of-range port should fail")
	}
}

// TestDrainGRPCIdleStopsPromptly checks the graceful path: an idle server drains
// well before the force-stop deadline.
func TestDrainGRPCIdleStopsPromptly(t *testing.T) {
	srv := grpc.NewServer()
	ln, err := listenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()

	done := make(chan struct{})
	go func() { drainGRPC(srv); close(done) }()
	select {
	case <-done:
	case <-time.After(drainTimeout):
		t.Fatal("idle server should drain well before drainTimeout")
	}
}
