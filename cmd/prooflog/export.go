package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/arhuman/prooflog/internal/anchor"
	"github.com/arhuman/prooflog/internal/export"
	"github.com/arhuman/prooflog/internal/keys"
	"github.com/arhuman/prooflog/internal/seal"
	"github.com/arhuman/prooflog/internal/verifier"
	"github.com/arhuman/prooflog/internal/version"
)

// runExport writes a forensic evidence bundle for one source: exact stored
// records, decrypted business payloads, covering checkpoints/anchors, and a
// signed chain-of-custody manifest (REQ-E-02). It is deliberately minimal — a
// linear scan with seq/time/actor filters, not a SIEM.
func runExport(args []string) error {
	if len(args) > 0 && args[0] == "verify" {
		return runExportVerify(args[1:])
	}

	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	storeAddr := fs.String("store-addr", "127.0.0.1:9700", "store gRPC address")
	source := fs.String("source", "", "source id to export (required)")
	fromSeq := fs.Uint64("from-seq", 0, "first seq to include (0: unbounded)")
	toSeq := fs.Uint64("to-seq", 0, "last seq to include (0: unbounded)")
	fromStr := fs.String("from", "", "earliest event_time to include (RFC3339)")
	toStr := fs.String("to", "", "latest event_time to include (RFC3339)")
	actor := fs.String("actor", "", "filter to one actor pseudonym (64-hex)")
	identityPath := fs.String("identity", "", "org key file to decrypt business payloads (required)")
	checkpoints := fs.String("checkpoints", "", "directory of signed checkpoints to include")
	anchors := fs.String("anchors", "", "directory of anchor receipts to include")
	keysPath := fs.String("keys", "", "registered keys JSON; bundles the source's public key(s) as keys.json for self-contained verification")
	out := fs.String("out", "", "output bundle directory (must be new/empty; required)")
	signKey := fs.String("sign-key", "", "ed25519 agent key to sign the manifest")
	tls := tlsFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" {
		return fmt.Errorf("--source is required")
	}
	if *identityPath == "" {
		return fmt.Errorf("--identity is required")
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}

	filter := export.Filter{FromSeq: *fromSeq, ToSeq: *toSeq, Actor: *actor}
	var err error
	if filter.FromTime, err = parseRFC3339(*fromStr); err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	if filter.ToTime, err = parseRFC3339(*toStr); err != nil {
		return fmt.Errorf("--to: %w", err)
	}

	orgKey, err := keys.LoadOrgKey(*identityPath)
	if err != nil {
		return err
	}
	var identity seal.Identity = orgKey.Identity

	var signer *keys.AgentKey
	if *signKey != "" {
		k, err := keys.LoadAgentKey(*signKey)
		if err != nil {
			return err
		}
		signer = &k
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	frames, err := pullEntries(ctx, *storeAddr, *source, tls)
	if err != nil {
		return err
	}

	var cps []string
	if *checkpoints != "" {
		if cps, err = verifier.LoadCheckpoints(*checkpoints, *source); err != nil {
			return err
		}
	}
	var receipts []anchor.Receipt
	if *anchors != "" {
		if receipts, err = anchor.LoadReceipts(*anchors, *source); err != nil {
			return err
		}
	}

	var pubKeys []verifier.SourceKey
	if *keysPath != "" {
		reg, err := verifier.LoadRegistry(*keysPath)
		if err != nil {
			return err
		}
		pubKeys = reg.SourceKeys(*source)
		if len(pubKeys) == 0 {
			return fmt.Errorf("--keys: no registered key for source %q", *source)
		}
	}

	man, err := export.Write(export.Options{
		SourceID:    *source,
		Frames:      frames,
		Filter:      filter,
		Identity:    identity,
		Checkpoints: cps,
		Anchors:     receipts,
		PublicKeys:  pubKeys,
		OutDir:      *out,
		ToolVersion: version.Version,
		BinaryHash:  binarySelfHash(),
		StoreAddr:   *storeAddr,
		Signer:      signer,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "exported %d records to %s (seq %d-%d, %d files)\n",
		man.RecordCount, *out, man.FirstSeq, man.LastSeq, len(man.Files))
	if signer != nil {
		fmt.Fprintf(os.Stderr, "manifest signed by %s (key %x)\n", signer.Name, signer.KeyID())
	}
	return nil
}

// runExportVerify re-verifies a bundle offline with the shipped binary: file
// hashes vs the manifest, the manifest signature, record integrity, and — for a
// whole-source bundle — the full chain and its binding to the signed
// checkpoints. It prints a PASS/FAIL summary and exits non-zero on any failure
// (REQ-E-02, REQ-E-05).
func runExportVerify(args []string) error {
	fs := flag.NewFlagSet("export verify", flag.ContinueOnError)
	verifyKey := fs.String("verify-key", "", "ed25519 key file whose public key signed the manifest (overrides bundled keys.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: prooflog export verify [--verify-key <key>] <bundle-dir>")
	}

	var opts export.VerifyOptions
	if *verifyKey != "" {
		k, err := keys.LoadAgentKey(*verifyKey)
		if err != nil {
			return err
		}
		opts.VerifyKey = &k
	}

	rep, err := export.VerifyBundle(fs.Arg(0), opts)
	if err != nil {
		return err
	}
	printExportVerifySummary(rep)
	if !rep.OK {
		return fmt.Errorf("bundle verification failed")
	}
	return nil
}

func printExportVerifySummary(rep export.VerifyReport) {
	fmt.Printf("Bundle verification — %s\n", rep.Dir)
	fmt.Printf("  source:  %s\n", rep.SourceID)
	fmt.Printf("  filter:  %s\n", rep.Filter)
	for _, c := range rep.Checks {
		fmt.Printf("  %s %s: %s\n", statusMark(c.Status), c.Label, c.Detail)
	}
	if rep.OK {
		fmt.Printf("\n  VERDICT: PASS — bundle is internally consistent.\n")
		return
	}
	fmt.Printf("\n  VERDICT: FAIL — bundle integrity could not be confirmed.\n")
}

func statusMark(s export.CheckStatus) string {
	switch s {
	case export.StatusPass:
		return "[PASS]"
	case export.StatusFail:
		return "[FAIL]"
	default:
		return "[info]"
	}
}

// parseRFC3339 parses an optional RFC3339 timestamp; "" yields the zero time.
func parseRFC3339(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}
