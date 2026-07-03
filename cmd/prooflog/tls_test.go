package main

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/arhuman/prooflog/internal/api"
)

// TestTLSFlagsDefaultSecure locks the secure-by-default contract: without an
// explicit --insecure, the parsed config must run with TLS (Insecure false).
func TestTLSFlagsDefaultSecure(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantInsecure bool
		wantMTLS     bool
	}{
		{"no flags is secure", nil, false, false},
		{"explicit opt-in", []string{"--insecure"}, true, false},
		{"mtls request", []string{"--tls-client-auth"}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			cfg := tlsFlags(fs)
			if err := fs.Parse(tt.args); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if cfg.Insecure != tt.wantInsecure {
				t.Fatalf("Insecure = %v, want %v", cfg.Insecure, tt.wantInsecure)
			}
			if cfg.ClientAuth != tt.wantMTLS {
				t.Fatalf("ClientAuth = %v, want %v", cfg.ClientAuth, tt.wantMTLS)
			}
		})
	}
}

// TestStoreClientNilFallbackSecure verifies the nil-TLS fallback resolves to the
// secure zero value, not silent plaintext: no insecure warning is emitted and a
// nil config never dials without TLS. grpc.NewClient is lazy, so no network I/O.
func TestStoreClientNilFallbackSecure(t *testing.T) {
	stderr := captureStderr(t, func() {
		_, cleanup, err := storeClient("passthrough:///x", nil)
		if err != nil {
			t.Fatalf("storeClient: %v", err)
		}
		cleanup()
	})
	if strings.Contains(stderr, "WARNING") {
		t.Fatalf("nil TLS fallback must be secure, got warning: %q", stderr)
	}

	stderr = captureStderr(t, func() {
		_, cleanup, err := storeClient("passthrough:///x", &api.TLSConfig{Insecure: true})
		if err != nil {
			t.Fatalf("storeClient: %v", err)
		}
		cleanup()
	})
	if !strings.Contains(stderr, "WARNING") {
		t.Fatalf("explicit Insecure must warn, got: %q", stderr)
	}
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what was
// written, so tests can assert on the insecure-transport warning.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = orig
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(out)
}
