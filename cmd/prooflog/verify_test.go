package main

import (
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/spool"
)

// buildCleanSpool writes one properly-chained heartbeat record to dir so that
// runVerify / gatherResult can process it without findings.
func buildCleanSpool(t *testing.T, dir string) {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	ts := envelope.FormatTime(now)
	rec := envelope.Record{
		Version:      envelope.Version,
		SourceID:     "vps-01/api",
		Seq:          1,
		EventType:    "system.heartbeat",
		EventTime:    ts,
		IngestTime:   ts,
		PayloadClear: []byte(`{"health":{"clock_drift_ms":10}}`),
		PrevHash:     envelope.ZeroHash,
	}
	if err := rec.Serialize(); err != nil {
		t.Fatal(err)
	}
	if err := sp.Append(rec); err != nil {
		t.Fatal(err)
	}
	_ = sp.Close()
}

// buildBrokenChainSpool writes two records where the second record's PrevHash
// does not link to the first, producing a chain.LinkError during verification.
func buildBrokenChainSpool(t *testing.T, dir string) {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	ts := envelope.FormatTime(now)
	rec1 := envelope.Record{
		Version:      envelope.Version,
		SourceID:     "vps-01/api",
		Seq:          1,
		EventType:    "system.heartbeat",
		EventTime:    ts,
		IngestTime:   ts,
		PayloadClear: []byte(`{"health":{"clock_drift_ms":10}}`),
		PrevHash:     envelope.ZeroHash,
	}
	if err := rec1.Serialize(); err != nil {
		t.Fatal(err)
	}
	if err := sp.Append(rec1); err != nil {
		t.Fatal(err)
	}

	// Second record: PrevHash intentionally wrong — should point to rec1.HashHex()
	// but we use ZeroHash, breaking the chain.
	ts2 := envelope.FormatTime(now.Add(60 * time.Second))
	rec2 := envelope.Record{
		Version:      envelope.Version,
		SourceID:     "vps-01/api",
		Seq:          2,
		EventType:    "system.heartbeat",
		EventTime:    ts2,
		IngestTime:   ts2,
		PayloadClear: []byte(`{"health":{"clock_drift_ms":10}}`),
		PrevHash:     envelope.ZeroHash, // deliberately wrong
	}
	if err := rec2.Serialize(); err != nil {
		t.Fatal(err)
	}
	if err := sp.Append(rec2); err != nil {
		t.Fatal(err)
	}
	_ = sp.Close()
}

// TestRunVerifyCleanSpool is the primary exit-code contract test: a properly
// chained spool with no findings must make runVerify return nil (exit 0).
func TestRunVerifyCleanSpool(t *testing.T) {
	dir := t.TempDir()
	buildCleanSpool(t, dir)

	if err := runVerify([]string{"--spool", dir}); err != nil {
		t.Fatalf("clean spool: expected nil error, got %v", err)
	}
}

// TestRunVerifyBrokenChain is the tamper-detection exit-code contract: a spool
// whose hash chain is broken must make runVerify return a non-nil error (exit 1).
func TestRunVerifyBrokenChain(t *testing.T) {
	dir := t.TempDir()
	buildBrokenChainSpool(t, dir)

	err := runVerify([]string{"--spool", dir})
	if err == nil {
		t.Fatal("broken chain spool: expected non-nil error, got nil")
	}
}

// TestRunVerifyBadPeriod ensures an invalid --period flag is rejected before
// any spool is read.
func TestRunVerifyBadPeriod(t *testing.T) {
	dir := t.TempDir()
	buildCleanSpool(t, dir)

	err := runVerify([]string{"--spool", dir, "--period", "not-a-date"})
	if err == nil {
		t.Fatal("expected error for malformed --period, got nil")
	}
}

// TestRunVerifyNoSource ensures that calling runVerify with neither --spool nor
// --store-addr is rejected with an appropriate error.
func TestRunVerifyNoSource(t *testing.T) {
	if err := runVerify([]string{}); err == nil {
		t.Fatal("expected error when no source is specified, got nil")
	}
}

// TestOkText exercises the small formatting helper used by printVerifySummary.
func TestOkText(t *testing.T) {
	if got := okText(true); got != "valid" {
		t.Fatalf("okText(true) = %q, want %q", got, "valid")
	}
	if got := okText(false); got != "BROKEN" {
		t.Fatalf("okText(false) = %q, want %q", got, "BROKEN")
	}
}
