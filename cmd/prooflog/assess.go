package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/arhuman/prooflog/internal/assess"
	"github.com/arhuman/prooflog/internal/evidence"
	"github.com/arhuman/prooflog/internal/report"
	"github.com/arhuman/prooflog/internal/version"
)

// Default input caps for assess. The input is a foreign, untrusted export, so
// the default read is bounded; hitting a cap is always loudly disclosed, never
// silent (REQ-E-16, ADR-0008). 0 is the explicit
// unlimited opt-out.
const (
	defaultAssessMaxRecords = 10_000_000
	defaultAssessMaxBytes   = 4 << 30 // 4 GiB
)

// stringSlice collects a repeatable --input flag.
type stringSlice []string

func (s *stringSlice) String() string { return fmt.Sprint(*s) }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// runAssess produces a Tier 0 Evidence Assessment Report over foreign JSONL
// (an export from another tool), running only the analyzers the mapped export
// supports (ADR-0008). It exits non-zero when any indicative finding is raised,
// mirroring `verify`, so it drops into CI and engagement scripts.
func runAssess(args []string) error {
	fs := flag.NewFlagSet("assess", flag.ContinueOnError)
	var inputs stringSlice
	fs.Var(&inputs, "input", "input JSONL file (repeatable; .gz auto-detected). '-' reads stdin")
	profileName := fs.String("profile", "generic", "mapping profile name or path to a .json profile")
	period := fs.String("period", "", "reporting window YYYY-MM-DD:YYYY-MM-DD (drives coverage checks)")
	heartbeatInterval := fs.Duration("heartbeat-interval", 0, "expected heartbeat interval (default: policy 60s)")
	maxSilence := fs.Duration("max-silence", 0, "max heartbeat silence before an observation gap (default: policy 3m)")
	org := fs.String("org", "", "organization name for the report header")
	reportID := fs.String("report-id", "", "report id (default: asr-<date>)")
	verifierName := fs.String("verifier-name", "prooflog assess", "identity shown in the header")
	out := fs.String("out", "", "output file (default: stdout)")
	jsonOut := fs.String("json", "", "also write machine-readable findings JSON to this file")
	maxRecords := fs.Int("max-records", defaultAssessMaxRecords, "stop after this many records (default 10,000,000; 0 disables the cap); truncation is disclosed")
	maxBytes := fs.Int64("max-bytes", defaultAssessMaxBytes, "stop after this many input bytes (default 4 GiB; 0 disables the cap); truncation is disclosed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(inputs) == 0 {
		return fmt.Errorf("provide at least one --input <file.jsonl> (or --input - for stdin)")
	}
	start, end, err := parsePeriod(*period)
	if err != nil {
		return err
	}

	profile, err := assess.LoadProfile(*profileName)
	if err != nil {
		return err
	}

	readers, closers, err := openInputs(inputs)
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range closers {
			c.Close()
		}
	}()

	in, err := assess.ReadLimited(profile, assess.Limits{MaxRecords: *maxRecords, MaxBytes: *maxBytes}, readers...)
	if err != nil {
		return err
	}
	if len(in.Sources) == 0 {
		return fmt.Errorf("no records parsed from input (check --profile matches the export shape)")
	}
	if in.Truncated {
		fmt.Fprintf(os.Stderr, "warning: input truncated — %s; the assessment is partial and says so\n", in.TruncReason)
	}

	policy := assess.DefaultPolicy()
	if *heartbeatInterval > 0 {
		policy.HeartbeatInterval = *heartbeatInterval
	}
	if *maxSilence > 0 {
		policy.MaxSilence = *maxSilence
	}
	window := assess.Window{Start: start, End: end}

	results := make([]assess.SourceResult, 0, len(in.Sources))
	totalFindings := 0
	for _, si := range in.Sources {
		res := assess.Assess(si, profile.Capabilities(), policy, window, in.Malformed)
		results = append(results, res)
		totalFindings += len(res.Findings)
	}

	id := *reportID
	if id == "" {
		id = "asr-" + time.Now().UTC().Format("2006-01-02")
	}
	meta := evidence.Meta{
		ReportID:     id,
		Org:          *org,
		PeriodStart:  start,
		PeriodEnd:    end,
		Generated:    time.Now().UTC(),
		VerifierName: *verifierName,
		ToolVersion:  version.Version,
	}
	model := report.BuildAssessModel(meta, results, in)
	doc, err := report.AssessMarkdown{}.Render(model)
	if err != nil {
		return err
	}

	if *out == "" {
		if _, err := os.Stdout.Write(doc); err != nil {
			return err
		}
	} else if err := os.WriteFile(*out, doc, 0o644); err != nil {
		return fmt.Errorf("write assessment: %w", err)
	} else {
		fmt.Fprintf(os.Stderr, "assessment written to %s\n", *out)
	}

	if *jsonOut != "" {
		if err := writeAssessJSON(*jsonOut, results); err != nil {
			return err
		}
	}

	if totalFindings > 0 {
		return fmt.Errorf("assessment raised %d indicative finding(s)", totalFindings)
	}
	return nil
}

// openInputs opens each --input path (or stdin for "-"), returning readers and
// closers. Gzip is detected transparently inside assess.Read.
func openInputs(paths []string) (readers []io.Reader, closers []io.Closer, err error) {
	for _, p := range paths {
		if p == "-" {
			readers = append(readers, os.Stdin)
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			for _, c := range closers {
				c.Close()
			}
			return nil, nil, err
		}
		readers = append(readers, f)
		closers = append(closers, f)
	}
	return readers, closers, nil
}

// assessFindingJSON is the machine-readable projection of one finding for the
// engagement tooling.
type assessFindingJSON struct {
	Source   string `json:"source"`
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

func writeAssessJSON(path string, results []assess.SourceResult) error {
	var findings []assessFindingJSON
	for _, s := range results {
		for _, f := range s.Findings {
			findings = append(findings, assessFindingJSON{
				Source: s.SourceID, ID: f.ID, Severity: string(f.Severity),
				Title: f.Title, Detail: f.Detail,
			})
		}
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write findings json: %w", err)
	}
	return nil
}
