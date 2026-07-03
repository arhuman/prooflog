package verifier

import (
	"os"
	"strings"
	"testing"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/note"
)

// A source's checkpoints (REQ-C-07) and anchor receipts (REQ-C-15) must share
// the same sanitized on-disk base name, and adversarial source IDs must never
// form path elements that escape the store directory.
func TestSanitizeSourceParityWithAnchorLog(t *testing.T) {
	t.Parallel()
	sources := []string{
		"..",
		"a.b",
		"a/b",
		`a\b`,
		"a b",
		"../../etc/passwd",
		"web-01.example.com/api",
	}
	for _, src := range sources {
		t.Run(src, func(t *testing.T) {
			t.Parallel()
			cpDir, anDir := t.TempDir(), t.TempDir()

			cs, err := OpenCheckpointStore(cpDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.Accept(src, "signed", note.Checkpoint{Origin: "o", Size: 1}); err != nil {
				t.Fatal(err)
			}
			al, err := anchor.OpenAnchorLog(anDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := al.Append(src, anchor.Receipt{Origin: "o", Size: 1}); err != nil {
				t.Fatal(err)
			}

			cpBase := strings.TrimSuffix(onlyEntry(t, cpDir), checkpointExt)
			anBase := strings.TrimSuffix(onlyEntry(t, anDir), ".anchors")
			if cpBase != anBase {
				t.Fatalf("checkpoint and anchor filenames diverge for %q: %q vs %q", src, cpBase, anBase)
			}
			if strings.ContainsAny(cpBase, `/\`) || strings.Contains(cpBase, "..") {
				t.Fatalf("sanitized name %q still contains path elements", cpBase)
			}
		})
	}
}

// onlyEntry returns the name of the single file written under dir, proving the
// store did not create the file elsewhere.
func onlyEntry(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one file in %s, got %d", dir, len(entries))
	}
	return entries[0].Name()
}
