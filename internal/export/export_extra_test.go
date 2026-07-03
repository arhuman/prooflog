package export

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/envelope"
)

// TestExportWithCheckpoints covers writeCheckpoints (currently 25%).
// TestExportWithAnchors covers writeAnchors (currently 20%).
func TestExportWithCheckpointsAndAnchors(t *testing.T) {
	f := newFixture(t)
	f.business(t, actorAlice, `{"user":"alice"}`)
	f.system(t)

	checkpoints := []string{
		"checkpoint line one\n",
		"checkpoint line two", // no trailing newline — writeCheckpoints must add it
	}
	anchors := []anchor.Receipt{
		{
			Origin:     "prooflog/acme/vps-01-api",
			Size:       2,
			RootB64:    "aGVsbG8=",
			TSA:        "http://tsa.example",
			GenTime:    time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
			AnchoredAt: time.Date(2026, 7, 3, 12, 0, 1, 0, time.UTC),
			Qualified:  false,
		},
	}

	out := filepath.Join(t.TempDir(), "bundle")
	man, err := Write(Options{
		SourceID:    "vps-01/api",
		Frames:      f.entries,
		Identity:    f.org.Identity,
		Checkpoints: checkpoints,
		Anchors:     anchors,
		OutDir:      out,
		ToolVersion: "test",
		BinaryHash:  "deadbeef",
		StoreAddr:   "127.0.0.1:9700",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := man.Files["checkpoints.txt"]; !ok {
		t.Fatal("checkpoints.txt must appear in manifest files map")
	}
	if _, ok := man.Files["anchors.jsonl"]; !ok {
		t.Fatal("anchors.jsonl must appear in manifest files map")
	}
}

// TestSortedFiles covers SortedFiles (currently 0%).
func TestSortedFiles(t *testing.T) {
	m := Manifest{
		Files: map[string]string{
			"zebra.txt":     "hash1",
			"alpha.jsonl":   "hash2",
			"manifest.json": "hash3",
		},
	}
	got := SortedFiles(m)
	if len(got) != 3 {
		t.Fatalf("SortedFiles: want 3 entries, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Fatalf("SortedFiles not sorted at index %d: %v", i, got)
		}
	}
}

// TestExportFilterToTime covers the t.After(f.ToTime) branch in Filter.matches.
func TestExportFilterToTime(t *testing.T) {
	f := newFixture(t)
	f.business(t, actorAlice, `{"user":"alice"}`) // seq 1: baseTime + 1min
	f.business(t, actorBob, `{"user":"bob"}`)     // seq 2: baseTime + 2min
	f.business(t, actorAlice, `{"user":"carol"}`) // seq 3: baseTime + 3min

	// Only seq 1 (baseTime+1min) is at or before baseTime+90s.
	out := filepath.Join(t.TempDir(), "bundle")
	man, err := Write(Options{
		SourceID:    "vps-01/api",
		Frames:      f.entries,
		Identity:    f.org.Identity,
		Filter:      Filter{ToTime: f.baseTime.Add(90 * time.Second)},
		OutDir:      out,
		ToolVersion: "test",
		BinaryHash:  "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if man.RecordCount != 1 {
		t.Fatalf("ToTime filter: record count = %d, want 1", man.RecordCount)
	}
}

// TestExportEmptyOutDir covers the empty-dir branch in ensureEmptyDir.
func TestExportEmptyOutDir(t *testing.T) {
	f := newFixture(t)
	f.system(t)
	if _, err := Write(Options{SourceID: "s", Frames: f.entries, OutDir: ""}); err == nil {
		t.Fatal("empty OutDir must return an error")
	}
}

// TestFilterMatchesInvalidEventTime covers the ParseTime error branch in Filter.matches.
// A record whose EventTime cannot be parsed must NOT match a time-bounded filter.
func TestFilterMatchesInvalidEventTime(t *testing.T) {
	rec := envelope.Record{
		Version:   envelope.Version,
		SourceID:  "s",
		Seq:       1,
		EventType: "system.heartbeat",
		EventTime: "not-a-valid-rfc3339-timestamp",
		PrevHash:  envelope.ZeroHash,
	}
	filter := Filter{FromTime: time.Now().Add(-time.Hour)}
	if filter.matches(rec) {
		t.Fatal("record with unparseable EventTime should not match a time filter")
	}
}
