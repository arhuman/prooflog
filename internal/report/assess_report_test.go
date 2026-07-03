package report

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/assess"
	"github.com/arhuman/prooflog/internal/evidence"
	"github.com/arhuman/prooflog/internal/hashid"
)

// sampleInputDigest is a fixed, valid whole-input digest for the sample model.
func sampleInputDigest() hashid.Digest {
	d, err := hashid.ParseHexDigest(strings.Repeat("deadbeef", 8))
	if err != nil {
		panic(err)
	}
	return d
}

func sampleAssessModel() AssessModel {
	meta := evidence.Meta{
		ReportID:     "asr-2026-07-05",
		Org:          "acme",
		VerifierName: "prooflog assess",
		ToolVersion:  "0.2.0-dev",
		Generated:    time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC),
		PeriodStart:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:    time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
		// Deliberately set fields that would make a continuity report Tier 2;
		// the assessment must still force Tier 0.
		VerifierOperator: "independent-auditor",
	}
	sources := []assess.SourceResult{{
		SourceID:    "idp/tenant-primary",
		Caps:        assess.Capabilities{Sequenced: false, Heartbeats: false},
		Records:     3,
		TimeFirst:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		TimeLast:    time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC),
		EventCounts: []evidence.EventCount{{Type: "idp.signin", Count: 3}},
		Findings: []evidence.Finding{{
			ID: "A-COVERAGE", Severity: evidence.SeverityMedium,
			Title: "export does not cover the full period", Detail: "…",
		}},
		Inputs: evidence.InputAttestation{RecordCount: 3, InputDigest: "abc123"},
	}}
	return BuildAssessModel(meta, sources, &assess.Input{Digest: sampleInputDigest(), Malformed: 0})
}

func TestAssessForcesTier0(t *testing.T) {
	m := sampleAssessModel()
	if m.Meta.Tier != evidence.TierAssessed {
		t.Fatalf("assessment must force Tier 0, got %v", m.Meta.Tier)
	}
	if m.Meta.DocumentTitle != "Evidence Assessment Report" {
		t.Errorf("unexpected document title %q", m.Meta.DocumentTitle)
	}
}

func TestAssessRenderNoProbativeIDs(t *testing.T) {
	out, err := AssessMarkdown{}.Render(sampleAssessModel())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(out)

	// A Tier 0 document must never carry a probative F-<n> finding id.
	if regexp.MustCompile(`\bF-\d+\b`).MatchString(doc) {
		t.Error("Tier 0 document must not contain an F-<n> probative finding id")
	}
	// It must never present itself as the continuity/integrity report.
	if strings.Contains(doc, "Continuity & Integrity Report") {
		t.Error("Tier 0 document must not use the continuity report title")
	}
	// The only mentions of attestation/certificate must be negations.
	assertOnlyNegated(t, doc, "cryptographically attested")
	assertOnlyNegated(t, doc, "verification certificate")
	// It must carry the loud Tier 0 banner and the A-* finding.
	for _, want := range []string{"TIER 0 — ASSESSMENT ONLY", "Evidence Assessment Report", "A-COVERAGE", "Upgrade path"} {
		if !strings.Contains(doc, want) {
			t.Errorf("Tier 0 document missing %q", want)
		}
	}
}

// assertOnlyNegated checks that every occurrence of phrase is immediately
// preceded by a negation ("no " or "not "), so the term appears only in
// disclaimers, never as a positive claim.
func assertOnlyNegated(t *testing.T, doc, phrase string) {
	t.Helper()
	for idx := 0; ; {
		i := strings.Index(doc[idx:], phrase)
		if i < 0 {
			return
		}
		at := idx + i
		prefix := strings.ToLower(doc[max(0, at-24):at])
		if !strings.Contains(prefix, "no ") && !strings.Contains(prefix, "not ") {
			t.Errorf("phrase %q appears without a preceding negation near: %q", phrase, doc[max(0, at-20):min(len(doc), at+len(phrase)+10)])
		}
		idx = at + len(phrase)
	}
}

func TestAssessRendersTruncationLoudly(t *testing.T) {
	m := sampleAssessModel()
	m.Truncated = true
	m.TruncReason = "--max-records 1000000 reached; remaining input not read"
	out, _ := AssessMarkdown{}.Render(m)
	doc := string(out)
	if !strings.Contains(doc, "INPUT TRUNCATED") {
		t.Error("a truncated assessment must render a loud truncation banner")
	}
	if !strings.Contains(doc, "1000000") {
		t.Error("the truncation reason should name the cap")
	}
	// A non-truncated assessment must not render the banner.
	clean := sampleAssessModel()
	cout, _ := AssessMarkdown{}.Render(clean)
	if strings.Contains(string(cout), "INPUT TRUNCATED") {
		t.Error("non-truncated assessment must not show the truncation banner")
	}
}

func TestAssessCleanStillWarns(t *testing.T) {
	m := sampleAssessModel()
	m.Sources[0].Findings = nil
	out, _ := AssessMarkdown{}.Render(m)
	doc := string(out)
	if !strings.Contains(doc, "not** proof of completeness") {
		t.Error("a clean assessment must still disclaim completeness proof")
	}
}
