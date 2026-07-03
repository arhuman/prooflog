package export

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/note"
	"github.com/arhuman/prooflog/internal/seal"
)

const (
	actorAlice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	actorBob   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fixture holds a chained record stream plus the keys used to build it.
type fixture struct {
	entries  []chain.Entry
	plain    map[uint64][]byte // seq -> decrypted business plaintext
	org      keys.OrgKey
	agent    keys.AgentKey
	recip    age.Recipient
	prev     string
	seq      uint64
	baseTime time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	org, err := keys.GenerateOrgKey("acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	agent, err := keys.GenerateAgentKey("vps-01-api", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recip, err := age.ParseX25519Recipient(org.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		plain:    map[uint64][]byte{},
		org:      org,
		agent:    agent,
		recip:    recip,
		prev:     envelope.ZeroHash,
		baseTime: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
	}
}

func (f *fixture) business(t *testing.T, actor string, payload string) {
	t.Helper()
	f.seq++
	plain := []byte(payload)
	ct, err := seal.AgeSealer{}.Seal(plain, []age.Recipient{f.recip})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plain)
	ts := envelope.FormatTime(f.baseTime.Add(time.Duration(f.seq) * time.Minute))
	rec := envelope.Record{
		Version: envelope.Version, SourceID: "vps-01/api", Seq: f.seq,
		EventType: "access.revoked", EventTime: ts, IngestTime: ts,
		Actor: actor, Outcome: "success",
		PayloadCT: seal.EncodeBase64(ct), PayloadHash: hex.EncodeToString(sum[:]),
		KeyID: "orgkey", PrevHash: f.prev,
	}
	f.finish(t, rec)
	f.plain[f.seq] = plain
}

func (f *fixture) system(t *testing.T) {
	t.Helper()
	f.seq++
	ts := envelope.FormatTime(f.baseTime.Add(time.Duration(f.seq) * time.Minute))
	rec := envelope.Record{
		Version: envelope.Version, SourceID: "vps-01/api", Seq: f.seq,
		EventType: "system.heartbeat", EventTime: ts, IngestTime: ts,
		PayloadClear: []byte(`{}`), PrevHash: f.prev,
	}
	f.finish(t, rec)
}

func (f *fixture) finish(t *testing.T, rec envelope.Record) {
	if err := rec.Serialize(); err != nil {
		t.Fatal(err)
	}
	if err := rec.Validate(); err != nil {
		t.Fatalf("record seq %d invalid: %v", rec.Seq, err)
	}
	f.entries = append(f.entries, chain.Entry{Bytes: rec.Bytes(), Hash: rec.HashHex()})
	f.prev = rec.HashHex()
}

func TestExportEndToEnd(t *testing.T) {
	f := newFixture(t)
	f.business(t, actorAlice, `{"user":"alice"}`)
	f.business(t, actorBob, `{"user":"bob"}`)
	f.system(t)

	out := filepath.Join(t.TempDir(), "bundle")
	man, err := Write(Options{
		SourceID: "vps-01/api", Frames: f.entries, Identity: f.org.Identity,
		OutDir: out, ToolVersion: "test", BinaryHash: "deadbeef", StoreAddr: "127.0.0.1:9700",
		Signer: &f.agent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if man.RecordCount != 3 || man.FirstSeq != 1 || man.LastSeq != 3 {
		t.Fatalf("unexpected manifest counts: %+v", man)
	}

	// records.jsonl is byte-for-byte the stored frames, one per line.
	var want []byte
	for _, e := range f.entries {
		want = append(want, e.Bytes...)
		want = append(want, '\n')
	}
	got, err := os.ReadFile(filepath.Join(out, "records.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("records.jsonl must equal the exact stored frames")
	}

	// Business payloads round-trip; the system event is not decrypted.
	for seq, plain := range f.plain {
		dec, err := os.ReadFile(filepath.Join(out, "decrypted", fmt.Sprintf("%d.json", seq)))
		if err != nil {
			t.Fatalf("decrypted seq %d: %v", seq, err)
		}
		if string(dec) != string(plain) {
			t.Fatalf("decrypted seq %d = %q, want %q", seq, dec, plain)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "decrypted", "3.json")); !os.IsNotExist(err) {
		t.Fatal("system event should not be decrypted")
	}

	// Every manifest per-file hash matches the file on disk.
	for name, want := range man.Files {
		b, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("manifest hash mismatch for %s", name)
		}
	}

	// The manifest signature verifies and covers the exact manifest bytes.
	sig, err := os.ReadFile(filepath.Join(out, "manifest.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	text, err := note.Verify(string(sig), f.agent.Name, f.agent.Public)
	if err != nil {
		t.Fatalf("manifest signature invalid: %v", err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if text != string(manifestBytes) {
		t.Fatal("signed text must equal manifest.json bytes")
	}
}

func TestExportFilters(t *testing.T) {
	f := newFixture(t)
	f.business(t, actorAlice, `{"user":"alice"}`) // seq 1
	f.business(t, actorBob, `{"user":"bob"}`)     // seq 2
	f.business(t, actorAlice, `{"user":"carol"}`) // seq 3

	tests := []struct {
		name     string
		filter   Filter
		wantSeqs []uint64
	}{
		{"seq range", Filter{FromSeq: 2, ToSeq: 3}, []uint64{2, 3}},
		{"actor", Filter{Actor: actorAlice}, []uint64{1, 3}},
		{"time from", Filter{FromTime: f.baseTime.Add(90 * time.Second)}, []uint64{2, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "bundle")
			man, err := Write(Options{
				SourceID: "vps-01/api", Frames: f.entries, Identity: f.org.Identity,
				Filter: tt.filter, OutDir: out, ToolVersion: "test", BinaryHash: "x",
			})
			if err != nil {
				t.Fatal(err)
			}
			if man.RecordCount != len(tt.wantSeqs) {
				t.Fatalf("record count = %d, want %d", man.RecordCount, len(tt.wantSeqs))
			}
		})
	}
}

func TestExportRefusesNonEmptyDir(t *testing.T) {
	f := newFixture(t)
	f.system(t)
	out := t.TempDir() // already exists and we drop a file in it
	if err := os.WriteFile(filepath.Join(out, "stale"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(Options{SourceID: "s", Frames: f.entries, OutDir: out}); err == nil {
		t.Fatal("export into a non-empty dir should be refused")
	}
}
