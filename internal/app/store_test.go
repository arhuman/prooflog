package app

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/arhuman/prooflog/internal/api"
)

// TestStoreAuthWarnings pins the privileged-gating matrix that used to live
// inline in cmd/prooflog/store.go behind flag parsing.
func TestStoreAuthWarnings(t *testing.T) {
	cases := []struct {
		name        string
		cfg         StoreConfig
		wantSubstrs []string
		wantN       int
	}{
		{
			name:        "allow unauthenticated: mutations and reads open",
			cfg:         StoreConfig{AllowUnauth: true},
			wantSubstrs: []string{"accept ANY caller", "read RPCs", "unauthenticated access explicitly allowed"},
			wantN:       3,
		},
		{
			name:        "insecure, no opt-out: mutations denied, reads open by default",
			cfg:         StoreConfig{TLS: api.TLSConfig{Insecure: true}},
			wantSubstrs: []string{"will be DENIED", "pass --require-read-auth to gate them"},
			wantN:       3,
		},
		{
			name:        "mTLS client auth, reads ungated: no mutation warning, default read warning",
			cfg:         StoreConfig{TLS: api.TLSConfig{ClientAuth: true}},
			wantSubstrs: []string{"OPEN to any caller; pass --require-read-auth"},
			wantN:       1,
		},
		{
			name:        "mTLS client auth, reads gated",
			cfg:         StoreConfig{TLS: api.TLSConfig{ClientAuth: true}, RequireReadAuth: true},
			wantSubstrs: []string{"GATED on mTLS client auth"},
			wantN:       1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := StoreAuthWarnings(tc.cfg)
			if len(got) != tc.wantN {
				t.Fatalf("warning count = %d, want %d\n%s", len(got), tc.wantN, strings.Join(got, "\n"))
			}
			joined := strings.Join(got, "\n")
			for _, sub := range tc.wantSubstrs {
				if !strings.Contains(joined, sub) {
					t.Errorf("warnings missing %q\n%s", sub, joined)
				}
			}
		})
	}
}

func TestStorePrivilege(t *testing.T) {
	const readMethod = "/prooflog.v1.StoreService/PullSegments"
	if storePrivilege(false)(readMethod) {
		t.Error("reads must not be privileged when RequireReadAuth is false")
	}
	if !storePrivilege(true)(readMethod) {
		t.Error("reads must be privileged when RequireReadAuth is true")
	}
}

// TestNewStoreServer assembles an insecure store server end to end and checks it
// wires the server, the opened store, and the matching warnings.
func TestNewStoreServer(t *testing.T) {
	dir := t.TempDir()
	ss, err := NewStoreServer(StoreConfig{
		DBPath:      filepath.Join(dir, "index.db"),
		BlobDir:     filepath.Join(dir, "blobs"),
		TLS:         api.TLSConfig{Insecure: true},
		AllowUnauth: true,
	})
	if err != nil {
		t.Fatalf("NewStoreServer: %v", err)
	}
	t.Cleanup(func() { _ = ss.Store.Close() })
	if ss.Server == nil || ss.Store == nil {
		t.Fatal("assembled server/store must be non-nil")
	}
	if len(ss.Warnings) != len(StoreAuthWarnings(StoreConfig{AllowUnauth: true})) {
		t.Fatalf("warnings not populated from config: %v", ss.Warnings)
	}
}
