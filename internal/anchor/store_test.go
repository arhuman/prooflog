package anchor

import (
	"path/filepath"
	"testing"
	"time"
)

func receipt(origin string, size uint64) Receipt {
	return Receipt{
		Origin:     origin,
		Size:       size,
		RootB64:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		TSA:        "https://tsa.example/tsr",
		Token:      []byte{0x30, 0x03, 0x02, 0x01, byte(size)},
		GenTime:    time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC),
		AnchoredAt: time.Date(2026, 7, 4, 2, 0, 1, 0, time.UTC),
	}
}

func TestAnchorLogAppendLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	log, err := OpenAnchorLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	const src = "vps-01/api"
	for _, size := range []uint64{2, 4, 8} {
		if err := log.Append(src, receipt("prooflog/acme/vps-01/api", size)); err != nil {
			t.Fatal(err)
		}
	}

	got, err := log.All(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("loaded %d receipts, want 3", len(got))
	}
	if got[0].Size != 2 || got[2].Size != 8 {
		t.Fatalf("receipt order not preserved: %d..%d", got[0].Size, got[2].Size)
	}

	// Package-level offline loader returns the same receipts.
	off, err := LoadReceipts(dir, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(off) != 3 || off[1].Size != 4 {
		t.Fatalf("LoadReceipts mismatch: %+v", off)
	}
}

func TestAnchorLogPerSourceIsolation(t *testing.T) {
	dir := t.TempDir()
	log, err := OpenAnchorLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append("vps-01/api", receipt("a", 1)); err != nil {
		t.Fatal(err)
	}
	if err := log.Append("vps-02/db", receipt("b", 9)); err != nil {
		t.Fatal(err)
	}

	a, _ := log.All("vps-01/api")
	b, _ := log.All("vps-02/db")
	if len(a) != 1 || a[0].Size != 1 {
		t.Fatalf("source a leaked: %+v", a)
	}
	if len(b) != 1 || b[0].Size != 9 {
		t.Fatalf("source b leaked: %+v", b)
	}
	// The sanitized filename mirrors the checkpoint store's scheme.
	if _, err := readReceipts(filepath.Join(dir, "vps-01_api.anchors")); err != nil {
		t.Fatalf("expected sanitized filename vps-01_api.anchors: %v", err)
	}
}

func TestAnchorLogPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	log1, err := OpenAnchorLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := log1.Append("s", receipt("o", 3)); err != nil {
		t.Fatal(err)
	}

	log2, err := OpenAnchorLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := log2.All("s")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Size != 3 {
		t.Fatalf("receipt not durable across reopen: %+v", got)
	}
}

func TestLoadReceiptsMissingFile(t *testing.T) {
	got, err := LoadReceipts(t.TempDir(), "never-written")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}
