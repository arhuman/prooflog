package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/api"
)

// ---- sanitize ---------------------------------------------------------------

func TestSanitize(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"vps-01/api", "vps-01-api"},
		{"foo bar", "foo-bar"},
		{"plain", "plain"},
		{"a/b/c", "a-b-c"},
	}
	for _, tt := range tests {
		if got := sanitize(tt.in); got != tt.want {
			t.Errorf("sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ---- resolveAddr ------------------------------------------------------------

func TestResolveAddrDirect(t *testing.T) {
	addr, err := resolveAddr("1.2.3.4:9600", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "1.2.3.4:9600" {
		t.Errorf("addr = %q, want %q", addr, "1.2.3.4:9600")
	}
}

func TestResolveAddrDefault(t *testing.T) {
	addr, err := resolveAddr("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "127.0.0.1:9600" {
		t.Errorf("addr = %q, want %q", addr, "127.0.0.1:9600")
	}
}

func TestResolveAddrInvalidConfig(t *testing.T) {
	_, err := resolveAddr("", filepath.Join(t.TempDir(), "nonexistent.json"))
	if err == nil {
		t.Fatal("expected error for nonexistent config path, got nil")
	}
}

// ---- labelFlag --------------------------------------------------------------

func TestLabelFlagSetValid(t *testing.T) {
	l := labelFlag{}
	if err := l.Set("env=prod"); err != nil {
		t.Fatalf("Set valid label: %v", err)
	}
	if l["env"] != "prod" {
		t.Errorf("label[env] = %q, want %q", l["env"], "prod")
	}
}

func TestLabelFlagSetInvalid(t *testing.T) {
	l := labelFlag{}
	if err := l.Set("no-equals-sign"); err == nil {
		t.Fatal("expected error for label without '=', got nil")
	}
}

func TestLabelFlagString(_ *testing.T) {
	l := labelFlag{}
	// String() must return a string (contract for flag.Value).
	_ = l.String()
}

// ---- binarySelfHash ---------------------------------------------------------

func TestBinarySelfHash(t *testing.T) {
	h := binarySelfHash()
	if h == "" {
		t.Fatal("binarySelfHash returned empty string")
	}
	// Running under `go test` the executable is available; hash should be
	// a 64-char lowercase hex string or the sentinel "unavailable".
	if h != "unavailable" && len(h) != 64 {
		t.Errorf("unexpected hash length %d: %q", len(h), h)
	}
}

// ---- holdRange --------------------------------------------------------------

func TestHoldRange(t *testing.T) {
	whole := &api.Hold{HasRange: false}
	if got := holdRange(whole); got != " (whole source)" {
		t.Errorf("whole-source hold: got %q", got)
	}

	ranged := &api.Hold{HasRange: true, SeqFirst: 10, SeqLast: 20}
	if got := holdRange(ranged); got != " seq 10-20" {
		t.Errorf("ranged hold: got %q", got)
	}
}

// ---- parseRFC3339 -----------------------------------------------------------

func TestParseRFC3339(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
		wantUTC bool
	}{
		{"empty", "", false, false},
		{"valid", "2026-07-03T12:00:00Z", false, true},
		{"invalid", "not-a-date", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRFC3339(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantUTC && got.Location() != time.UTC {
				t.Errorf("expected UTC location, got %v", got.Location())
			}
		})
	}
}

// ---- runSpool dispatch -------------------------------------------------------

func TestRunSpoolNoArgs(t *testing.T) {
	if err := runSpool([]string{}); err == nil {
		t.Fatal("expected error with no subcommand, got nil")
	}
}

func TestRunSpoolUnknown(t *testing.T) {
	if err := runSpool([]string{"unknown-sub"}); err == nil {
		t.Fatal("expected error for unknown spool subcommand, got nil")
	}
}

// TestRunSpoolCatEmptyDir exercises runSpoolCat against a spool directory that
// has no frames — it must still succeed (return nil).
func TestRunSpoolCatEmptyDir(t *testing.T) {
	dir := t.TempDir()
	if err := runSpool([]string{"cat", dir}); err != nil {
		t.Fatalf("runSpool cat empty dir: %v", err)
	}
}

// TestRunSpoolCatWithRecords exercises runSpoolCat against a populated spool.
func TestRunSpoolCatWithRecords(t *testing.T) {
	dir := t.TempDir()
	buildCleanSpool(t, dir)
	if err := runSpool([]string{"cat", dir}); err != nil {
		t.Fatalf("runSpool cat with records: %v", err)
	}
}

// TestRunSpoolCatNoDir exercises the missing-dir argument path.
func TestRunSpoolCatNoDir(t *testing.T) {
	if err := runSpool([]string{"cat"}); err == nil {
		t.Fatal("expected error for spool cat with no dir, got nil")
	}
}

// ---- runVersion -------------------------------------------------------------

func TestRunVersion(t *testing.T) {
	if err := runVersion([]string{}); err != nil {
		t.Fatalf("runVersion: %v", err)
	}
}

// ---- hold subcommand validation (pre-dial, no server needed) ----------------

func TestRunHoldNoSubcommand(t *testing.T) {
	if err := runHold([]string{}); err == nil {
		t.Fatal("expected error with no subcommand, got nil")
	}
}

func TestRunHoldUnknownSubcommand(t *testing.T) {
	if err := runHold([]string{"unknown"}); err == nil {
		t.Fatal("expected error for unknown hold subcommand, got nil")
	}
}

func TestRunHoldPlaceMissingSource(t *testing.T) {
	err := runHold([]string{"place", "--reason", "test"})
	if err == nil {
		t.Fatal("expected error for missing --source, got nil")
	}
}

func TestRunHoldPlaceMissingReason(t *testing.T) {
	err := runHold([]string{"place", "--source", "vps-01/api"})
	if err == nil {
		t.Fatal("expected error for missing --reason, got nil")
	}
}

func TestRunHoldPlaceInvalidSeqRange(t *testing.T) {
	// from-seq > to-seq must be rejected before dialing.
	err := runHold([]string{
		"place",
		"--source", "vps-01/api",
		"--reason", "test",
		"--from-seq", "10",
		"--to-seq", "5",
	})
	if err == nil {
		t.Fatal("expected error for invalid seq range (from > to), got nil")
	}
}

func TestRunHoldReleaseNoID(t *testing.T) {
	err := runHold([]string{"release"})
	if err == nil {
		t.Fatal("expected error for missing --id, got nil")
	}
}

// ---- export validation (pre-dial, no server needed) -------------------------

func TestRunExportMissingSource(t *testing.T) {
	if err := runExport([]string{}); err == nil {
		t.Fatal("expected error for missing --source, got nil")
	}
}

func TestRunExportMissingIdentity(t *testing.T) {
	err := runExport([]string{"--source", "vps-01/api"})
	if err == nil {
		t.Fatal("expected error for missing --identity, got nil")
	}
}

func TestRunExportMissingOut(t *testing.T) {
	err := runExport([]string{
		"--source", "vps-01/api",
		"--identity", "/nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for missing --out, got nil")
	}
}

func TestRunExportBadFromTime(t *testing.T) {
	err := runExport([]string{
		"--source", "vps-01/api",
		"--identity", "/nonexistent",
		"--out", t.TempDir(),
		"--from", "not-a-date",
	})
	if err == nil {
		t.Fatal("expected error for invalid --from time, got nil")
	}
}
