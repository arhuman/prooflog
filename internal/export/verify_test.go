package export

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/merkle"
	"github.com/arhuman/prooflog/internal/note"
	"github.com/arhuman/prooflog/internal/verifier"
)

// checkpointOverAll builds a signed checkpoint committing to the Merkle root of
// every entry in the fixture, using the fixture's agent key.
func (f *fixture) checkpointOverAll(t *testing.T, size uint64, root [32]byte) string {
	t.Helper()
	cp := note.Checkpoint{Origin: "prooflog/acme/vps-01-api", Size: size, Hash: root}
	signed, err := note.Sign(cp.Marshal(), f.agent.Name, f.agent.Private)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (f *fixture) rootOfAll() [32]byte {
	raw := make([][]byte, len(f.entries))
	for i, e := range f.entries {
		raw[i] = e.Bytes
	}
	return merkle.RootFromEntries(raw)
}

func (f *fixture) sourceKey() verifier.SourceKey {
	return verifier.SourceKey{
		SourceID:  "vps-01/api",
		Origin:    "prooflog/acme/vps-01-api",
		KeyName:   f.agent.Name,
		PublicKey: f.agent.Public,
	}
}

// exportWholeSource writes a whole-source bundle with the given checkpoints, the
// bundled public key, and a signed manifest. It returns the bundle directory.
func (f *fixture) exportWholeSource(t *testing.T, checkpoints []string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "bundle")
	if _, err := Write(Options{
		SourceID:    "vps-01/api",
		Frames:      f.entries,
		Identity:    f.org.Identity,
		Checkpoints: checkpoints,
		PublicKeys:  []verifier.SourceKey{f.sourceKey()},
		OutDir:      out,
		ToolVersion: "test",
		BinaryHash:  "deadbeef",
		StoreAddr:   "127.0.0.1:9700",
		Signer:      &f.agent,
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func failLines(rep VerifyReport) []string {
	var out []string
	for _, c := range rep.Checks {
		if c.Status == StatusFail {
			out = append(out, c.Label+": "+c.Detail)
		}
	}
	return out
}

func TestVerifyBundleWholeSourceOK(t *testing.T) {
	f := newFixture(t)
	f.business(t, actorAlice, `{"user":"alice"}`)
	f.business(t, actorBob, `{"user":"bob"}`)
	f.system(t)

	cp := f.checkpointOverAll(t, uint64(len(f.entries)), f.rootOfAll())
	out := f.exportWholeSource(t, []string{cp})

	rep, err := VerifyBundle(out, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("expected OK bundle, got failures: %v", failLines(rep))
	}
	if !rep.Signed || rep.Signer != f.agent.Name {
		t.Fatalf("expected signed by %s, got signed=%v signer=%q", f.agent.Name, rep.Signed, rep.Signer)
	}
	if !rep.WholeSource {
		t.Fatal("bundle should be reported as whole-source")
	}
}

func TestVerifyBundleRecordTampered(t *testing.T) {
	f := newFixture(t)
	f.business(t, actorAlice, `{"user":"alice"}`)
	f.system(t)

	cp := f.checkpointOverAll(t, uint64(len(f.entries)), f.rootOfAll())
	out := f.exportWholeSource(t, []string{cp})

	// Flip a byte in records.jsonl.
	path := filepath.Join(out, "records.jsonl")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifyBundle(out, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("tampered records.jsonl must fail verification")
	}
	if len(failLines(rep)) == 0 {
		t.Fatal("expected at least one failure line")
	}
}

func TestVerifyBundleManifestEdited(t *testing.T) {
	f := newFixture(t)
	f.business(t, actorAlice, `{"user":"alice"}`)
	f.system(t)

	cp := f.checkpointOverAll(t, uint64(len(f.entries)), f.rootOfAll())
	out := f.exportWholeSource(t, []string{cp})

	// Edit manifest.json after it was signed: change a non-compared field so only
	// the signature check catches it.
	path := filepath.Join(out, "manifest.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := []byte(strings.Replace(string(b), `"operator"`, `"0perator"`, 1))
	if string(edited) == string(b) {
		t.Fatal("manifest edit did not change bytes")
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifyBundle(out, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("edited manifest.json must fail signature verification")
	}
	var sawSig bool
	for _, c := range rep.Checks {
		if c.Status == StatusFail && c.Label == "manifest signature" {
			sawSig = true
		}
	}
	if !sawSig {
		t.Fatalf("expected a manifest signature failure, got: %v", failLines(rep))
	}
}

func TestVerifyBundleWrongCheckpointRoot(t *testing.T) {
	f := newFixture(t)
	f.business(t, actorAlice, `{"user":"alice"}`)
	f.business(t, actorBob, `{"user":"bob"}`)

	// Valid chain, but the checkpoint commits to a wrong (all-0xAA) root.
	var wrong [32]byte
	for i := range wrong {
		wrong[i] = 0xAA
	}
	cp := f.checkpointOverAll(t, uint64(len(f.entries)), wrong)
	out := f.exportWholeSource(t, []string{cp})

	rep, err := VerifyBundle(out, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("checkpoint over a wrong root must fail verification")
	}
	var sawBinding bool
	for _, c := range rep.Checks {
		if c.Status == StatusFail && c.Label == "checkpoint binding" {
			sawBinding = true
		}
	}
	if !sawBinding {
		t.Fatalf("expected a checkpoint binding failure, got: %v", failLines(rep))
	}
}

func TestSplitCheckpointsRoundTrip(t *testing.T) {
	agent, err := keys.GenerateAgentKey("vps-01-api", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cp1 := note.Checkpoint{Origin: "o", Size: 1, Hash: [32]byte{1}}
	cp2 := note.Checkpoint{Origin: "o", Size: 2, Hash: [32]byte{2}}
	s1, err := note.Sign(cp1.Marshal(), agent.Name, agent.Private)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := note.Sign(cp2.Marshal(), agent.Name, agent.Private)
	if err != nil {
		t.Fatal(err)
	}

	// Concatenate exactly as writeCheckpoints does.
	files := map[string]string{}
	dir := t.TempDir()
	if err := writeCheckpoints(dir, []string{s1, s2}, files); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "checkpoints.txt"))
	if err != nil {
		t.Fatal(err)
	}

	notes := splitCheckpoints(data)
	if len(notes) != 2 {
		t.Fatalf("split returned %d notes, want 2", len(notes))
	}
	if notes[0] != s1 || notes[1] != s2 {
		t.Fatal("split notes do not round-trip to the original signed notes")
	}
	for _, signed := range notes {
		if _, err := note.Verify(signed, agent.Name, agent.Public); err != nil {
			t.Fatalf("split note failed to verify: %v", err)
		}
	}
}
