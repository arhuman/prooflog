package export

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/note"
	"github.com/arhuman/prooflog/internal/verifier"
)

// noteSigPrefix mirrors the unexported note.sigPrefix: the em dash (U+2014) then
// a space that begins every C2SP signature line. Used to split concatenated
// signed checkpoints and to read a manifest signature's signer name.
const noteSigPrefix = "— "

// integrityFindingPrefixes are the verifier finding IDs that count as bundle
// integrity failures during `export verify`. Continuity/clock findings
// (F-GAP-*, F-CLOCK) are reported as informational, not failures.
var integrityFindingPrefixes = []string{"F-CHAIN", "F-FORK", "F-SIG", "F-ANCHOR", "F-RETENTION"}

// CheckStatus classifies one verification line.
type CheckStatus int

const (
	// StatusPass marks a check that confirms integrity.
	StatusPass CheckStatus = iota
	// StatusFail marks an integrity failure; any StatusFail makes the verdict FAIL.
	StatusFail
	// StatusInfo marks a non-failing observation (e.g. unsigned, filtered subset).
	StatusInfo
)

// Check is one line of a bundle verification report.
type Check struct {
	Status CheckStatus
	Label  string
	Detail string
}

// VerifyReport is the outcome of re-verifying a bundle offline. OK is the single
// overall verdict: true only when no check failed.
type VerifyReport struct {
	Dir         string
	SourceID    string
	Filter      string
	WholeSource bool
	Signed      bool
	Signer      string
	KeyID       string
	Checks      []Check
	OK          bool
}

func (r *VerifyReport) add(status CheckStatus, label, detail string) {
	r.Checks = append(r.Checks, Check{Status: status, Label: label, Detail: detail})
}

// VerifyOptions configures VerifyBundle.
type VerifyOptions struct {
	// VerifyKey optionally overrides the manifest signer's public key; when nil
	// the signer is looked up in the bundled keys.json.
	VerifyKey *keys.AgentKey
}

// VerifyBundle re-verifies a forensic evidence bundle offline: file hashes vs
// the manifest, the manifest signature, record integrity vs the manifest, and —
// for a whole-source bundle — the full hash chain and its binding to the signed
// checkpoints. It never trusts the exporter: every check recomputes from the
// bundle's own bytes. The returned report's OK is false if any integrity check
// failed (REQ-E-02, REQ-E-05).
func VerifyBundle(dir string, opts VerifyOptions) (VerifyReport, error) {
	rep := VerifyReport{Dir: dir}

	manBytes, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return rep, fmt.Errorf("export verify: read manifest.json: %w", err)
	}
	var man Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return rep, fmt.Errorf("export verify: parse manifest.json: %w", err)
	}
	rep.SourceID = man.SourceID
	rep.Filter = man.Filter
	rep.WholeSource = man.Filter == wholeSourceFilter

	verifyFileIntegrity(dir, man, &rep)
	keyring := loadBundleKeyring(dir)
	verifyManifestSig(dir, manBytes, opts.VerifyKey, keyring, &rep)
	entries, recordsOK := verifyRecordIntegrity(dir, man, &rep)

	switch {
	case !rep.WholeSource:
		rep.add(StatusInfo, "chain/checkpoints",
			"filtered bundle: the record subset is intentionally non-contiguous, so "+
				"chain and checkpoint-root recomputation is not applicable; integrity "+
				"rests on the per-record hashes and the signed manifest")
	case !recordsOK:
		rep.add(StatusInfo, "chain/checkpoints",
			"skipped: records.jsonl could not be parsed (see record integrity)")
	default:
		verifyChainBinding(dir, man, entries, keyring, &rep)
	}

	rep.OK = true
	for _, c := range rep.Checks {
		if c.Status == StatusFail {
			rep.OK = false
			break
		}
	}
	return rep, nil
}

// loadBundleKeyring loads keys.json (if present) into a verifier.Keyring keyed
// by key name. A missing keys.json yields an empty keyring, not an error.
func loadBundleKeyring(dir string) verifier.Keyring {
	reg, err := verifier.LoadRegistry(filepath.Join(dir, "keys.json"))
	if err != nil {
		return nil
	}
	ring := verifier.Keyring{}
	for _, sk := range reg.Sources() {
		ring[sk.KeyName] = sk.PublicKey
	}
	return ring
}

// verifyFileIntegrity recomputes every manifest-listed file's SHA-256 and flags
// mismatches, missing files, and on-disk files absent from the manifest (only
// manifest.json and manifest.json.sig are legitimately unlisted).
func verifyFileIntegrity(dir string, man Manifest, rep *VerifyReport) {
	var failures []string
	for name, want := range man.Files {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			failures = append(failures, name+": missing or unreadable")
			continue
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			failures = append(failures, name+": SHA-256 mismatch")
		}
	}
	for _, rel := range walkBundle(dir) {
		if rel == "manifest.json" || rel == "manifest.json.sig" {
			continue
		}
		if _, ok := man.Files[rel]; !ok {
			failures = append(failures, rel+": present on disk but not listed in manifest")
		}
	}
	if len(failures) > 0 {
		rep.add(StatusFail, "file integrity", strings.Join(failures, "; "))
		return
	}
	rep.add(StatusPass, "file integrity",
		fmt.Sprintf("%d files match manifest SHA-256", len(man.Files)))
}

// walkBundle returns every regular file under dir as a bundle-relative path.
func walkBundle(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if rel, relErr := filepath.Rel(dir, p); relErr == nil {
			out = append(out, rel)
		}
		return nil
	})
	return out
}

// verifyManifestSig verifies manifest.json.sig as a C2SP note over the exact
// bytes of manifest.json. The signer key is opts.VerifyKey if provided, else the
// note's key name resolved against the bundled keyring. An absent .sig is
// reported (unsigned) but is not a failure.
func verifyManifestSig(dir string, manBytes []byte, override *keys.AgentKey, keyring verifier.Keyring, rep *VerifyReport) {
	sigBytes, err := os.ReadFile(filepath.Join(dir, "manifest.json.sig"))
	if os.IsNotExist(err) {
		rep.add(StatusInfo, "manifest signature", "unsigned (no manifest.json.sig)")
		return
	}
	if err != nil {
		rep.add(StatusFail, "manifest signature", fmt.Sprintf("read: %v", err))
		return
	}
	signed := string(sigBytes)

	var name string
	var pub ed25519.PublicKey
	switch {
	case override != nil:
		name, pub = override.Name, override.Public
	default:
		n, ok := noteSignerName(signed)
		if !ok {
			rep.add(StatusFail, "manifest signature", "cannot parse signer name from signature")
			return
		}
		p, ok := keyring[n]
		if !ok {
			rep.add(StatusFail, "manifest signature",
				fmt.Sprintf("no public key for signer %q (provide --verify-key or bundle keys.json)", n))
			return
		}
		name, pub = n, p
	}

	text, err := note.Verify(signed, name, pub)
	if err != nil {
		rep.add(StatusFail, "manifest signature", fmt.Sprintf("invalid: %v", err))
		return
	}
	if text != string(manBytes) {
		rep.add(StatusFail, "manifest signature", "signature does not cover manifest.json bytes")
		return
	}
	kid := note.KeyID(name, pub)
	rep.Signed = true
	rep.Signer = name
	rep.KeyID = hex.EncodeToString(kid[:])
	rep.add(StatusPass, "manifest signature",
		fmt.Sprintf("valid — signed by %s (key %x)", name, kid))
}

// noteSignerName extracts the signer name from a signed note's signature line.
func noteSignerName(signed string) (string, bool) {
	split := strings.LastIndex(signed, "\n\n")
	if split < 0 {
		return "", false
	}
	line := signed[split+2:]
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if !strings.HasPrefix(line, noteSigPrefix) {
		return "", false
	}
	rest := line[len(noteSigPrefix):]
	sp := strings.IndexByte(rest, ' ')
	if sp < 0 {
		return "", false
	}
	return rest[:sp], true
}

// verifyRecordIntegrity parses records.jsonl and recomputes the record count,
// seq bounds, and first/last hashes, comparing them to the manifest. It returns
// the parsed chain entries for the whole-source chain check.
// verifyRecordIntegrity returns the parsed chain entries and a bool that is false
// when records.jsonl could not be read or parsed (so the caller skips the chain
// check rather than claiming a spurious pass over empty input).
func verifyRecordIntegrity(dir string, man Manifest, rep *VerifyReport) ([]chain.Entry, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		rep.add(StatusFail, "record integrity", fmt.Sprintf("read records.jsonl: %v", err))
		return nil, false
	}
	var records []envelope.Record
	var entries []chain.Entry
	for _, line := range strings.Split(string(b), "\n") {
		if len(line) == 0 {
			continue
		}
		rec, err := envelope.Parse([]byte(line))
		if err != nil {
			rep.add(StatusFail, "record integrity", fmt.Sprintf("parse record: %v", err))
			return nil, false
		}
		records = append(records, rec)
		entries = append(entries, chain.Entry{Bytes: []byte(line), Hash: rec.HashHex()})
	}

	var mism []string
	if len(records) != man.RecordCount {
		mism = append(mism, fmt.Sprintf("record_count %d != manifest %d", len(records), man.RecordCount))
	}
	if len(records) > 0 {
		first, last := records[0], records[len(records)-1]
		if first.Seq != man.FirstSeq {
			mism = append(mism, fmt.Sprintf("first_seq %d != manifest %d", first.Seq, man.FirstSeq))
		}
		if last.Seq != man.LastSeq {
			mism = append(mism, fmt.Sprintf("last_seq %d != manifest %d", last.Seq, man.LastSeq))
		}
		if first.HashHex() != man.FirstHash {
			mism = append(mism, "first_record_sha256 mismatch")
		}
		if last.HashHex() != man.LastHash {
			mism = append(mism, "last_record_sha256 mismatch")
		}
	}
	if len(mism) > 0 {
		rep.add(StatusFail, "record integrity", strings.Join(mism, "; "))
		return entries, true
	}
	rep.add(StatusPass, "record integrity",
		fmt.Sprintf("%d records match manifest seq/hash bounds", len(records)))
	return entries, true
}

// verifyChainBinding (whole-source bundles only) re-verifies the full hash chain,
// confirms the chain head matches the manifest, then — if checkpoints.txt and
// keys.json are present — runs the offline verifier to bind the chain to the
// independent signed checkpoints. Only integrity-class findings fail the verdict.
func verifyChainBinding(dir string, man Manifest, entries []chain.Entry, keyring verifier.Keyring, rep *VerifyReport) {
	if err := chain.Verify(entries); err != nil {
		rep.add(StatusFail, "hash chain", fmt.Sprintf("chain broken: %v", err))
		return
	}
	if len(entries) > 0 {
		head := entries[len(entries)-1].Hash
		if head != man.ChainHead {
			rep.add(StatusFail, "hash chain",
				fmt.Sprintf("chain head %s != manifest %s", head, man.ChainHead))
			return
		}
	}
	rep.add(StatusPass, "hash chain",
		"records form a contiguous verified chain matching the manifest head")

	cpBytes, err := os.ReadFile(filepath.Join(dir, "checkpoints.txt"))
	if os.IsNotExist(err) {
		rep.add(StatusInfo, "checkpoints",
			"no checkpoints.txt in bundle; chain verified without an independent commitment")
		return
	}
	if err != nil {
		rep.add(StatusFail, "checkpoints", fmt.Sprintf("read checkpoints.txt: %v", err))
		return
	}
	if len(keyring) == 0 {
		rep.add(StatusInfo, "checkpoints",
			"no keys.json; cannot verify checkpoint signatures (provide the signer's key via a trusted channel)")
		return
	}

	notes := splitCheckpoints(cpBytes)
	src := verifier.Source{SourceID: man.SourceID, Entries: entries, Checkpoints: notes}
	res := verifier.Verify(src, keyring, verifier.DefaultPolicy())

	integrityFailures := 0
	for _, f := range res.Findings {
		if isIntegrityFinding(f.ID) {
			integrityFailures++
			rep.add(StatusFail, "checkpoint binding",
				fmt.Sprintf("[%s] %s: %s", f.ID, f.Title, f.Detail))
		} else {
			rep.add(StatusInfo, "continuity", fmt.Sprintf("[%s] %s", f.ID, f.Title))
		}
	}
	if integrityFailures == 0 {
		rep.add(StatusPass, "checkpoints",
			fmt.Sprintf("%d signed, %d roots valid, consistent=%v — chain bound to signed checkpoints",
				res.Checkpoints.SignaturesValid, res.Checkpoints.RootsValid, res.Checkpoints.Consistent))
	}
}

func isIntegrityFinding(id string) bool {
	for _, p := range integrityFindingPrefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// splitCheckpoints reconstructs each signed C2SP note from checkpoints.txt (the
// concatenation writeCheckpoints produced). A note is text lines followed by a
// single signature line beginning with noteSigPrefix, which is always last; that
// line closes the current note.
func splitCheckpoints(data []byte) []string {
	var notes []string
	var buf []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, noteSigPrefix) {
			notes = append(notes, strings.Join(append(buf, line), "\n")+"\n")
			buf = nil
			continue
		}
		buf = append(buf, line)
	}
	return notes
}

// verifyDoc is the static VERIFY.md shipped in every bundle.
const verifyDoc = `# Verifying this evidence bundle

This directory is a **prooflog forensic evidence bundle** for one source. It is
designed to be verified by a third party **without trusting whoever exported
it**: every claim can be recomputed from the bytes in this directory.

## What is here

- ` + "`manifest.json`" + ` — the chain-of-custody record. Its ` + "`files`" + ` map lists the
  SHA-256 of every other bundle file. Its ` + "`filter`" + ` field says whether this is a
  whole-source bundle or a filtered subset.
- ` + "`manifest.json.sig`" + ` — (optional) a C2SP signed note over the exact bytes of
  ` + "`manifest.json`" + `.
- ` + "`records.jsonl`" + ` — the exact stored record bytes, one JSON object per line.
- ` + "`decrypted/`" + ` — (optional) business payloads decrypted at export time.
- ` + "`checkpoints.txt`" + ` — (optional) the signed C2SP tlog-checkpoints emitted by the
  independent verifier for this source.
- ` + "`anchors.jsonl`" + ` — (optional) external RFC 3161 timestamp receipts.
- ` + "`keys.json`" + ` — (optional) the source's registered Ed25519 **public** key(s), so
  signature and checkpoint verification is self-contained.

## Primary path: one command

From inside this directory, with the shipped ` + "`prooflog`" + ` binary:

    prooflog export verify .

It recomputes every file's SHA-256 against ` + "`manifest.json`" + `, verifies the manifest
signature, re-derives the record count/seq/hash bounds, and — for a whole-source
bundle — re-verifies the full hash chain and its binding to the signed
checkpoints. It prints a PASS/FAIL verdict and **exits non-zero on any integrity
failure**.

If the manifest was signed by a key you obtained through a trusted channel
(rather than the bundled ` + "`keys.json`" + `), pass it explicitly:

    prooflog export verify --verify-key <signer.key> .

## Manual path: no prooflog binary

1. **File hashes.** For every entry in ` + "`manifest.json`" + `'s ` + "`files`" + ` map, compute the
   file's SHA-256 (e.g. ` + "`sha256sum <file>`" + `) and confirm it equals the listed
   value. Only ` + "`manifest.json`" + ` and ` + "`manifest.json.sig`" + ` are not self-listed.
2. **Manifest signature.** If ` + "`manifest.json.sig`" + ` is present, it is a C2SP signed
   note over the **exact bytes** of ` + "`manifest.json`" + `. To check it you need the
   signer's Ed25519 public key — found in ` + "`keys.json`" + ` when present, otherwise
   obtained from the operator via a trusted channel.
3. **Records.** ` + "`records.jsonl`" + ` holds the exact stored record bytes, one JSON
   object per line; each object's own hash chains to the previous record's.
4. **Checkpoints.** ` + "`checkpoints.txt`" + ` holds the signed tlog-checkpoints from the
   independent verifier; each commits (via an RFC 6962 Merkle root) to the
   record history.

## Honest scope (read this)

A signed manifest whose signing key is **bundled here** only proves the bundle is
**internally consistent** — it does not prove authenticity on its own. Authenticity
requires obtaining the signer's public key through a **trusted channel** independent
of this bundle, then verifying against that key.

- **Whole-source bundle** (` + "`filter`" + ` is ` + "`none (whole source)`" + `): ` + "`export verify`" + `
  re-checks the **full hash chain** and its binding to the **independent signed
  checkpoints**. This is the strongest offline guarantee.
- **Filtered bundle** (a seq / time / actor filter is shown in ` + "`filter`" + `): the record
  subset intentionally does **not** form a contiguous chain, and the checkpoint
  Merkle root cannot be recomputed from a subset. Integrity then rests on the
  **per-record hashes plus the signed manifest**. Full checkpoint re-verification
  requires re-exporting the **whole source**.
`
