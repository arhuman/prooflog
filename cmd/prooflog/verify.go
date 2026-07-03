package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/arhuman/prooflog/internal/verifier"
)

// runVerify runs the offline verification engine over a spool directory or a
// store pull, prints a findings summary, and exits non-zero if any finding is
// raised (REQ-C-02, REQ-E-05, REQ-E-10).
func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	spoolDir := fs.String("spool", "", "local spool directory to verify")
	storeAddr := fs.String("store-addr", "", "pull records from this store instead of a spool")
	source := fs.String("source", "", "source id (required with --store-addr)")
	checkpoints := fs.String("checkpoints", "", "directory of signed checkpoints (verifier data dir)")
	anchors := fs.String("anchors", "", "directory of anchor receipts (default: none)")
	keysPath := fs.String("keys", "", "registered keys JSON for checkpoint signature checks")
	period := fs.String("period", "", "reporting window YYYY-MM-DD:YYYY-MM-DD (informational)")
	heartbeatInterval := fs.Duration("heartbeat-interval", 0, "expected heartbeat interval (default: policy 60s)")
	tls := tlsFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, _, err := parsePeriod(*period); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, sourceID, err := gatherResult(ctx, verifyOpts{
		spoolDir:          *spoolDir,
		storeAddr:         *storeAddr,
		sourceID:          *source,
		checkpointsDir:    *checkpoints,
		anchorsDir:        *anchors,
		keysPath:          *keysPath,
		heartbeatInterval: *heartbeatInterval,
		tls:               tls,
	})
	if err != nil {
		return err
	}

	printVerifySummary(sourceID, *period, res)
	if len(res.Findings) > 0 {
		return fmt.Errorf("verification raised %d finding(s)", len(res.Findings))
	}
	return nil
}

func printVerifySummary(sourceID, period string, res verifier.SourceResult) {
	fmt.Printf("Verification — source %s\n", sourceID)
	if period != "" {
		fmt.Printf("  period:       %s\n", period)
	}
	fmt.Printf("  seq range:    %d → %d\n", res.SeqFirst, res.SeqLast)
	fmt.Printf("  hash chain:   %s\n", okText(res.Chain.Valid))
	fmt.Printf("  checkpoints:  %d signed, %d roots valid, consistent=%v\n",
		res.Checkpoints.SignaturesValid, res.Checkpoints.RootsValid, res.Checkpoints.Consistent)
	fmt.Printf("  observation:  %d heartbeats, longest gap %s, within policy=%v\n",
		res.Continuity.Summary.Observed, res.Continuity.Summary.LongestGap.Round(time.Second),
		res.Continuity.Summary.WithinPolicy)
	fmt.Printf("  transport:    %d outage(s), longest %s, buffered %d, replay complete=%v\n",
		res.Transport.Outages, res.Transport.LongestOutage.Round(time.Second),
		res.Transport.BufferedEvents, res.Transport.ReplayCompleted)
	fmt.Printf("  max drift:    %dms\n", res.MaxClockDriftMS)

	if len(res.Findings) == 0 {
		fmt.Printf("\n  VERDICT: clean — no findings.\n")
		return
	}
	fmt.Printf("\n  FINDINGS (%d):\n", len(res.Findings))
	for _, f := range res.Findings {
		fmt.Printf("   - [%s] %s: %s\n", f.Severity, f.ID, f.Title)
	}
}

func okText(ok bool) string {
	if ok {
		return "valid"
	}
	return "BROKEN"
}
