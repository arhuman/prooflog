// Package export writes a forensic evidence bundle for one source: the exact
// stored record bytes, decrypted business payloads, the covering signed
// checkpoints and anchors, and a signed chain-of-custody manifest (REQ-E-02).
//
// It is deliberately minimal — NOT a SIEM. There is no index or query language:
// a linear scan over the pulled frames applies at most a seq range, an
// event_time range, and an actor-pseudonym equality filter.
package export

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/chain"
	"github.com/arhuman/prooflog/internal/envelope"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/note"
	"github.com/arhuman/prooflog/internal/seal"
	"github.com/arhuman/prooflog/internal/verifier"
)

// wholeSourceFilter is the manifest Filter value for an unfiltered (whole
// source) bundle: only such a bundle re-forms a contiguous chain and permits
// full checkpoint-root recomputation during `export verify`.
const wholeSourceFilter = "none (whole source)"

// Filter selects records from the pulled range. Zero values mean "unbounded":
// FromSeq/ToSeq of 0 impose no seq bound, zero times impose no time bound, and
// an empty Actor matches any actor.
type Filter struct {
	FromSeq  uint64
	ToSeq    uint64
	FromTime time.Time
	ToTime   time.Time
	Actor    string
}

// matches reports whether rec passes the filter.
func (f Filter) matches(rec envelope.Record) bool {
	if f.FromSeq != 0 && rec.Seq < f.FromSeq {
		return false
	}
	if f.ToSeq != 0 && rec.Seq > f.ToSeq {
		return false
	}
	if f.Actor != "" && rec.Actor != f.Actor {
		return false
	}
	if !f.FromTime.IsZero() || !f.ToTime.IsZero() {
		t, err := envelope.ParseTime(rec.EventTime)
		if err != nil {
			return false
		}
		if !f.FromTime.IsZero() && t.Before(f.FromTime) {
			return false
		}
		if !f.ToTime.IsZero() && t.After(f.ToTime) {
			return false
		}
	}
	return true
}

// expr renders the filter as a human-readable expression for the manifest.
func (f Filter) expr() string {
	var parts []string
	if f.FromSeq != 0 || f.ToSeq != 0 {
		parts = append(parts, fmt.Sprintf("seq %d..%d", f.FromSeq, f.ToSeq))
	}
	if !f.FromTime.IsZero() || !f.ToTime.IsZero() {
		parts = append(parts, fmt.Sprintf("event_time %s..%s",
			envelope.FormatTime(f.FromTime), envelope.FormatTime(f.ToTime)))
	}
	if f.Actor != "" {
		parts = append(parts, "actor="+f.Actor)
	}
	if len(parts) == 0 {
		return wholeSourceFilter
	}
	return strings.Join(parts, "; ")
}

// Options configures a bundle export.
type Options struct {
	SourceID    string
	Frames      []chain.Entry        // all pulled frames for the source, in seq order
	Filter      Filter               // linear-scan record filter
	Identity    seal.Identity        // org key to decrypt business payloads
	Checkpoints []string             // covering signed checkpoint notes
	Anchors     []anchor.Receipt     // optional anchor receipts
	PublicKeys  []verifier.SourceKey // source's registered public key(s), bundled as keys.json
	OutDir      string               // bundle output directory (must be empty/new)
	ToolVersion string
	BinaryHash  string
	StoreAddr   string
	Signer      *keys.AgentKey // optional manifest signer
}

// Manifest is the chain-of-custody record for a bundle (REQ-E-02). Files maps
// each bundle file's path (relative to the bundle dir) to its SHA-256.
type Manifest struct {
	Tool        string            `json:"tool"`
	ToolVersion string            `json:"tool_version"`
	BinarySHA   string            `json:"binary_sha256"`
	GeneratedAt string            `json:"generated_at"`
	Operator    string            `json:"operator"`
	StoreAddr   string            `json:"store_addr"`
	SourceID    string            `json:"source_id"`
	Filter      string            `json:"filter"`
	RecordCount int               `json:"record_count"`
	FirstSeq    uint64            `json:"first_seq"`
	LastSeq     uint64            `json:"last_seq"`
	FirstHash   string            `json:"first_record_sha256"`
	LastHash    string            `json:"last_record_sha256"`
	ChainHead   string            `json:"chain_head_sha256"`
	Files       map[string]string `json:"files"`
}

// Write runs the export pipeline: refuse a non-empty output dir, chain-verify
// the pulled range, filter, write the bundle files, then write (and optionally
// sign) the custody manifest. It returns the manifest for inspection/tests.
func Write(opts Options) (Manifest, error) {
	if err := ensureEmptyDir(opts.OutDir); err != nil {
		return Manifest{}, err
	}
	if err := chain.Verify(opts.Frames); err != nil {
		return Manifest{}, fmt.Errorf("export: pulled range does not chain-verify: %w", err)
	}

	records := make([]envelope.Record, 0, len(opts.Frames))
	for i, e := range opts.Frames {
		rec, err := envelope.Parse(e.Bytes)
		if err != nil {
			return Manifest{}, fmt.Errorf("export: parse frame %d: %w", i, err)
		}
		records = append(records, rec)
	}
	chainHead := ""
	if len(records) > 0 {
		chainHead = records[len(records)-1].HashHex()
	}

	var filtered []envelope.Record
	for _, rec := range records {
		if opts.Filter.matches(rec) {
			filtered = append(filtered, rec)
		}
	}

	files := map[string]string{}
	if err := os.MkdirAll(opts.OutDir, 0o700); err != nil {
		return Manifest{}, fmt.Errorf("export: mkdir bundle: %w", err)
	}

	if err := writeRecords(opts.OutDir, filtered, files); err != nil {
		return Manifest{}, err
	}
	if err := writeDecrypted(opts.OutDir, filtered, opts.Identity, files); err != nil {
		return Manifest{}, err
	}
	if err := writeCheckpoints(opts.OutDir, opts.Checkpoints, files); err != nil {
		return Manifest{}, err
	}
	if err := writeAnchors(opts.OutDir, opts.Anchors, files); err != nil {
		return Manifest{}, err
	}
	if err := writeKeys(opts.OutDir, opts.PublicKeys, files); err != nil {
		return Manifest{}, err
	}
	if err := writeVerifyDoc(opts.OutDir, files); err != nil {
		return Manifest{}, err
	}

	man := buildManifest(opts, filtered, chainHead, files)
	if err := writeManifest(opts, man); err != nil {
		return Manifest{}, err
	}
	return man, nil
}

func ensureEmptyDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("export: --out bundle directory is required")
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("export: read out dir: %w", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("export: bundle directory %s is not empty; refusing to overwrite", dir)
	}
	return nil
}

// writeRecords writes the exact stored bytes of each filtered record, one JSON
// object per line, byte-for-byte identical to the stored frames (REQ-C-04).
func writeRecords(dir string, records []envelope.Record, files map[string]string) error {
	var buf []byte
	for _, rec := range records {
		buf = append(buf, rec.Bytes()...)
		buf = append(buf, '\n')
	}
	return writeFile(dir, "records.jsonl", buf, files)
}

// writeDecrypted decrypts each business event's payload_ct with the identity and
// writes the plaintext (which may be the {"labels":…,"data":…} wrapper). System
// events are skipped: their payload is already clear in records.jsonl.
func writeDecrypted(dir string, records []envelope.Record, identity seal.Identity, files map[string]string) error {
	if identity == nil {
		return nil
	}
	sealer := seal.AgeSealer{}
	subdir := filepath.Join(dir, "decrypted")
	made := false
	for _, rec := range records {
		if rec.IsSystem() || rec.PayloadCT == "" {
			continue
		}
		ct, err := seal.DecodeBase64(rec.PayloadCT)
		if err != nil {
			return fmt.Errorf("export: decode payload_ct seq %d: %w", rec.Seq, err)
		}
		plain, err := sealer.Open(ct, identity)
		if err != nil {
			return fmt.Errorf("export: decrypt seq %d: %w", rec.Seq, err)
		}
		if !made {
			if err := os.MkdirAll(subdir, 0o700); err != nil {
				return fmt.Errorf("export: mkdir decrypted: %w", err)
			}
			made = true
		}
		name := filepath.Join("decrypted", fmt.Sprintf("%d.json", rec.Seq))
		if err := writeFile(dir, name, plain, files); err != nil {
			return err
		}
	}
	return nil
}

func writeCheckpoints(dir string, checkpoints []string, files map[string]string) error {
	if len(checkpoints) == 0 {
		return nil
	}
	var buf []byte
	for _, cp := range checkpoints {
		buf = append(buf, cp...)
		if !strings.HasSuffix(cp, "\n") {
			buf = append(buf, '\n')
		}
	}
	return writeFile(dir, "checkpoints.txt", buf, files)
}

func writeAnchors(dir string, anchors []anchor.Receipt, files map[string]string) error {
	if len(anchors) == 0 {
		return nil
	}
	var buf []byte
	for _, a := range anchors {
		line, err := json.Marshal(a)
		if err != nil {
			return fmt.Errorf("export: marshal anchor: %w", err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	return writeFile(dir, "anchors.jsonl", buf, files)
}

// writeKeys bundles the source's registered public key(s) as keys.json in the
// exact on-disk registry shape verifier.LoadRegistry reads, so signature and
// checkpoint verification is self-contained. Public keys only (REQ-C-11).
func writeKeys(dir string, pubKeys []verifier.SourceKey, files map[string]string) error {
	if len(pubKeys) == 0 {
		return nil
	}
	type keyJSON struct {
		SourceID  string `json:"source_id"`
		Origin    string `json:"origin"`
		KeyName   string `json:"key_name"`
		PublicKey string `json:"public_key"`
	}
	var doc struct {
		Sources []keyJSON `json:"sources"`
	}
	for _, k := range pubKeys {
		doc.Sources = append(doc.Sources, keyJSON{
			SourceID:  k.SourceID,
			Origin:    k.Origin,
			KeyName:   k.KeyName,
			PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey),
		})
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("export: marshal keys: %w", err)
	}
	b = append(b, '\n')
	return writeFile(dir, "keys.json", b, files)
}

// writeVerifyDoc writes VERIFY.md: static, human-readable instructions for a
// third party to re-verify the bundle without trusting the exporter. It embeds
// no per-run hashes so it can be written before (and thus be covered by) the
// manifest.
func writeVerifyDoc(dir string, files map[string]string) error {
	return writeFile(dir, "VERIFY.md", []byte(verifyDoc), files)
}

func buildManifest(opts Options, records []envelope.Record, chainHead string, files map[string]string) Manifest {
	man := Manifest{
		Tool:        "prooflog",
		ToolVersion: opts.ToolVersion,
		BinarySHA:   opts.BinaryHash,
		GeneratedAt: envelope.FormatTime(time.Now()),
		Operator:    operator(),
		StoreAddr:   opts.StoreAddr,
		SourceID:    opts.SourceID,
		Filter:      opts.Filter.expr(),
		RecordCount: len(records),
		ChainHead:   chainHead,
		Files:       files,
	}
	if len(records) > 0 {
		man.FirstSeq = records[0].Seq
		man.LastSeq = records[len(records)-1].Seq
		man.FirstHash = records[0].HashHex()
		man.LastHash = records[len(records)-1].HashHex()
	}
	return man
}

// writeManifest writes manifest.json (trailing newline) and, when a signer is
// configured, a C2SP signed note over those exact bytes to manifest.json.sig.
func writeManifest(opts Options, man Manifest) error {
	b, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return fmt.Errorf("export: marshal manifest: %w", err)
	}
	b = append(b, '\n')
	path := filepath.Join(opts.OutDir, "manifest.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("export: write manifest: %w", err)
	}
	if opts.Signer == nil {
		return nil
	}
	signed, err := note.Sign(string(b), opts.Signer.Name, opts.Signer.Private)
	if err != nil {
		return fmt.Errorf("export: sign manifest: %w", err)
	}
	if err := os.WriteFile(path+".sig", []byte(signed), 0o600); err != nil {
		return fmt.Errorf("export: write manifest signature: %w", err)
	}
	return nil
}

// writeFile writes bundle-relative name and records its SHA-256 in files.
func writeFile(dir, name string, data []byte, files map[string]string) error {
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		return fmt.Errorf("export: write %s: %w", name, err)
	}
	sum := sha256.Sum256(data)
	files[name] = hex.EncodeToString(sum[:])
	return nil
}

// operator identifies who ran the export: "<username>@<hostname>".
func operator() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return name + "@" + host
}

// SortedFiles returns the bundle file paths in deterministic order (test helper).
func SortedFiles(m Manifest) []string {
	out := make([]string, 0, len(m.Files))
	for k := range m.Files {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
