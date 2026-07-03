package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arhuman/prooflog/internal/api"
	"github.com/arhuman/prooflog/internal/store"
)

// ===== Shared helpers =========================================================

// newInsecureStoreServer opens a store in a temp dir, registers it on a gRPC
// server bound to 127.0.0.1:0 (insecure transport, unauthenticated holds),
// serves in a goroutine, and returns the network address. Cleanup is registered
// on t.
func newInsecureStoreServer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(store.Config{
		DBPath:  filepath.Join(dir, "index.db"),
		BlobDir: filepath.Join(dir, "blobs"),
	})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	// RequireMTLS(true, ...) permits unauthenticated privileged RPCs so tests can
	// drive PlaceHold / ReleaseHold without mTLS.
	srv, err := api.NewServer(api.TLSConfig{Insecure: true}, api.RequireMTLS(true, api.StorePrivileged)...)
	if err != nil {
		t.Fatalf("api.NewServer: %v", err)
	}
	api.RegisterStore(srv, s)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = s.Close()
	})
	return ln.Addr().String()
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// was written. It mirrors captureStderr in tls_test.go; do not call t.Fatal
// inside fn or the pipe will remain open.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = orig
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

// ===== hold place =============================================================

// TestRunHoldPlaceHappyPath verifies the whole-source hold happy path against a
// live (insecure) store: runHold returns nil and stdout contains "hold placed:"
// and the source id.
func TestRunHoldPlaceHappyPath(t *testing.T) {
	addr := newInsecureStoreServer(t)

	var runErr error
	out := captureStdout(t, func() {
		runErr = runHold([]string{
			"place",
			"--store-addr", addr,
			"--insecure",
			"--source", "vps-01/api",
			"--reason", "litigation hold Q1",
		})
	})
	if runErr != nil {
		t.Fatalf("runHold place: %v", runErr)
	}
	if !strings.Contains(out, "hold placed:") {
		t.Errorf("stdout missing 'hold placed:': %q", out)
	}
	if !strings.Contains(out, "vps-01/api") {
		t.Errorf("stdout missing source id 'vps-01/api': %q", out)
	}
}

// ===== hold list ==============================================================

// TestRunHoldListEmpty verifies that listing holds on a store with no holds
// prints "no holds" and returns nil.
func TestRunHoldListEmpty(t *testing.T) {
	addr := newInsecureStoreServer(t)

	var runErr error
	out := captureStdout(t, func() {
		runErr = runHold([]string{"list", "--store-addr", addr, "--insecure"})
	})
	if runErr != nil {
		t.Fatalf("runHold list empty: %v", runErr)
	}
	if !strings.Contains(out, "no holds") {
		t.Errorf("expected 'no holds' in stdout, got: %q", out)
	}
}

// ===== round-trip: place × 2 → list → release → list ========================

// TestRunHoldRoundTrip exercises the full hold lifecycle:
//  1. Place hold A (whole-source).
//  2. Place hold B (ranged: seq 1-5).
//  3. List → both shows as [active].
//  4. Release hold A by parsed id.
//  5. List → hold A released, hold B still [active].
func TestRunHoldRoundTrip(t *testing.T) {
	addr := newInsecureStoreServer(t)

	// -- 1. Place hold A (whole-source). ---------------------------------------
	var placeErr error
	placeOut := captureStdout(t, func() {
		placeErr = runHold([]string{
			"place", "--store-addr", addr, "--insecure",
			"--source", "vps-01/api",
			"--reason", "hold-A",
		})
	})
	if placeErr != nil {
		t.Fatalf("place hold A: %v", placeErr)
	}
	// Output: "hold placed: <id> on vps-01/api (whole source) (reason: hold-A)"
	// The hold id is the third whitespace-delimited token.
	fields := strings.Fields(placeOut)
	if len(fields) < 3 {
		t.Fatalf("unexpected place-A output: %q", placeOut)
	}
	holdAID := fields[2]

	// -- 2. Place hold B (ranged). --------------------------------------------
	if err := runHold([]string{
		"place", "--store-addr", addr, "--insecure",
		"--source", "vps-01/api",
		"--reason", "hold-B",
		"--from-seq", "1",
		"--to-seq", "5",
	}); err != nil {
		t.Fatalf("place hold B: %v", err)
	}

	// -- 3. List: both holds active. ------------------------------------------
	var listErr error
	listOut1 := captureStdout(t, func() {
		listErr = runHold([]string{"list", "--store-addr", addr, "--insecure"})
	})
	if listErr != nil {
		t.Fatalf("list after place: %v", listErr)
	}
	if strings.Count(listOut1, "[active]") < 2 {
		t.Errorf("expected ≥2 [active] lines after placing two holds; got:\n%s", listOut1)
	}

	// -- 4. Release hold A. ---------------------------------------------------
	if err := runHold([]string{
		"release", "--store-addr", addr, "--insecure",
		"--id", holdAID,
	}); err != nil {
		t.Fatalf("release hold A: %v", err)
	}

	// -- 5. List: hold A released, hold B still active. -----------------------
	var listErr2 error
	listOut2 := captureStdout(t, func() {
		listErr2 = runHold([]string{"list", "--store-addr", addr, "--insecure"})
	})
	if listErr2 != nil {
		t.Fatalf("list after release: %v", listErr2)
	}
	if !strings.Contains(listOut2, "released") {
		t.Errorf("expected 'released' in list output after releasing hold A; got:\n%s", listOut2)
	}
	if strings.Count(listOut2, "[active]") != 1 {
		t.Errorf("expected exactly 1 [active] hold after release; got:\n%s", listOut2)
	}
}

// ===== hold release: unknown id ==============================================

// TestRunHoldReleaseUnknownID verifies that releasing a non-existent hold id
// returns a non-nil error (exit-code contract: store returns NOT_FOUND).
func TestRunHoldReleaseUnknownID(t *testing.T) {
	addr := newInsecureStoreServer(t)
	err := runHold([]string{
		"release", "--store-addr", addr, "--insecure",
		"--id", "nonexistent-hold-id",
	})
	if err == nil {
		t.Fatal("expected error releasing nonexistent hold, got nil")
	}
}
