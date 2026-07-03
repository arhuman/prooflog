package report

import (
	"strings"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/evidence"
	"github.com/arhuman/prooflog/internal/verifier"
)

func okResult() verifier.SourceResult {
	return verifier.SourceResult{
		SourceID:    "vps-01/api",
		Origin:      "prooflog/acme/vps-01/api",
		SeqFirst:    1,
		SeqLast:     300,
		Chain:       verifier.ChainCheck{Valid: true},
		Checkpoints: verifier.CheckpointCheck{Total: 2, SignaturesValid: 2, RootsValid: 2, Consistent: true},
		Continuity: verifier.ContinuityCheck{Summary: evidence.ContinuitySummary{
			IntervalSeconds: 60, MaxSilence: 3 * time.Minute, Expected: 300, Observed: 300,
			LongestGap: 124 * time.Second, WithinPolicy: true,
		}},
		Transport: verifier.TransportCheck{Outages: 1, LongestOutage: 512 * time.Second, BufferedEvents: 441, ReplayCompleted: true},
	}
}

func TestBuildModelStatus(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*verifier.SourceResult)
		wantStatus string
		wantInteg  string
	}{
		{"all good", func(*verifier.SourceResult) {}, "OK", "Valid"},
		{"broken chain", func(r *verifier.SourceResult) { r.Chain = verifier.ChainCheck{Valid: false} }, "FAIL", "INVALID"},
		{
			name: "unobserved window",
			mutate: func(r *verifier.SourceResult) {
				r.Continuity.Summary.WithinPolicy = false
				r.Continuity.Windows = []verifier.Window{{Bounded: false}}
			},
			wantStatus: "ATTENTION",
			wantInteg:  "Valid",
		},
		{
			name: "inconsistent checkpoints",
			mutate: func(r *verifier.SourceResult) {
				r.Checkpoints.Consistent = false
			},
			wantStatus: "FAIL",
			wantInteg:  "INVALID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := okResult()
			tt.mutate(&r)
			m := BuildModel(evidence.Meta{ReportID: "rpt-1"}, []verifier.SourceResult{r})
			if m.Meta.Schema != "prooflog.report/v1" {
				t.Fatalf("schema default not applied: %q", m.Meta.Schema)
			}
			s := m.Sources[0]
			if s.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", s.Status, tt.wantStatus)
			}
			if s.Integrity != tt.wantInteg {
				t.Fatalf("integrity = %q, want %q", s.Integrity, tt.wantInteg)
			}
		})
	}
}

func TestMarkdownRenderContainsKeySections(t *testing.T) {
	meta := evidence.Meta{
		ReportID:     "rpt-2026-07-03-a41f",
		Org:          "acme-corp",
		PeriodStart:  time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
		PeriodEnd:    time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC),
		Generated:    time.Date(2026, 7, 3, 6, 0, 12, 0, time.UTC),
		VerifierName: "verifier.prooflog.example",
	}
	meta.VerifierOperator = "Example Verifier Ltd"
	meta.Reproduce = "prooflog verify --spool ./demo/spool"
	r := okResult()
	r.KeyID = "org-acme-2026-1"
	r.Encrypted = true
	r.EventCounts = []evidence.EventCount{{Type: "deploy.completed", Count: 3}}
	r.Findings = []evidence.Finding{{
		ID: "F-GAP-1", Severity: evidence.SeverityMedium, Title: "unobserved window on vps-02/db",
		Detail: "no heartbeat for 47m", Recommendation: "enable auto-start",
	}}
	m := BuildModel(meta, []verifier.SourceResult{r})

	out, err := Markdown{}.Render(m)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"# Prooflog — Continuity & Integrity Report",
		"rpt-2026-07-03-a41f",
		"acme-corp",
		"| **Period** | 2026-06-30 00:00:00 UTC → 2026-07-03 00:00:00 UTC (72h) |",
		"| **Sources covered** | `vps-01/api` |",
		"## 1. Verdict",
		"## 2. What this report proves — and what it does not",
		"content-blind",
		"`vps-01/api`",
		"## 3. Continuity of observation",
		"## 4. Transport & outage tolerance",
		"## 5. Integrity",
		"### 5.4 Clock drift",
		"External timestamp anchor: **not configured** — checkpoint times rest on",
		"## 6. Critical events recorded (evidence summary)",
		"`deploy.completed`",
		"## 7. Privacy manifest",
		"| `actor` | pseudonymous (HMAC-SHA256, per-subject erasable salt) |",
		"| `payload`, labels | encrypted (age, organization key) |",
		"HMAC-SHA256 with a per-subject 256-bit salt",
		"per-subject payload keys are planned",
		"organization `org-acme-2026-1`",
		"## 8. Findings",
		"F-1 — unobserved window on vps-02/db — severity: medium.",
		"*Recommendation:* enable auto-start",
		"## 9. Trust assumptions & limitations",
		"operated by Example Verifier Ltd, independent from the operator",
		"## 10. Reproduce this verification",
		"prooflog verify --spool ./demo/spool",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered report missing %q\n---\n%s", want, got)
		}
	}
}

func TestMarkdownDefensiveWordingAndProvenance(t *testing.T) {
	meta := evidence.Meta{
		ReportID:           "rpt-ws2",
		ToolVersion:        "0.2.0-test",
		VerifierBinaryHash: "abc123def456",
	}
	r := okResult()
	r.Inputs = evidence.InputAttestation{
		RecordCount:   3,
		InputDigest:   "deadbeef",
		CheckpointIDs: []string{"prooflog/acme/vps-01/api@3 root=AAAAAAAAAAAA…"},
	}
	m := BuildModel(meta, []verifier.SourceResult{r})
	out, err := Markdown{}.Render(m)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	wants := []string{
		"Verified against the records available to the verifier",
		"no gap detected ≠ no event was omitted before it reached the agent",
		"| **Tool version** | `0.2.0-test` |",
		"| **Verifier binary (SHA-256)** | `abc123def456` |",
		"### 5.5 Inputs & algorithms",
		"SHA-256 (FIPS 180-4)",
		"Ed25519 (RFC 8032 / FIPS 186-5)",
		"RFC 6962 §2.1 Merkle tree",
		"C2SP signed-note / tlog-checkpoint",
		"age X25519 + ChaCha20-Poly1305 (RFC 8439)",
	}
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered report missing %q\n---\n%s", want, got)
		}
	}
}

func TestMarkdownSelfHostedCaveat(t *testing.T) {
	m := BuildModel(evidence.Meta{SelfHosted: true}, []verifier.SourceResult{okResult()})
	out, err := Markdown{}.Render(m)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.Contains(got, "Verifier independence — NOT satisfied") {
		t.Fatalf("self-hosted report must state the caveat\n---\n%s", got)
	}
	if !strings.Contains(got, "self-hosted — **not independent**") {
		t.Fatalf("self-hosted header line missing\n---\n%s", got)
	}
}

func TestMarkdownLocality(t *testing.T) {
	tests := []struct {
		name             string
		storeLocality    string
		verifierLocality string
		wants            []string
	}{
		{
			name:             "both declared",
			storeLocality:    "CH",
			verifierLocality: "EU/DE",
			wants: []string{
				"| **Store locality** | CH (declared by operator; not proven) |",
				"| **Verifier locality** | EU/DE (declared by operator; not proven) |",
				"Store and verifier localities are operator declarations recorded for chain of custody; " +
					"they are not cryptographically proven.",
			},
		},
		{
			name:             "none declared",
			storeLocality:    "",
			verifierLocality: "",
			wants: []string{
				"| **Store locality** | — (not declared) |",
				"| **Verifier locality** | — (not declared) |",
				"Component locality was not (fully) declared by the operator; data-residency posture " +
					"cannot be assessed from this report (see docs/data_residency.md).",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := evidence.Meta{
				ReportID:         "rpt-ws3",
				StoreLocality:    tt.storeLocality,
				VerifierLocality: tt.verifierLocality,
			}
			m := BuildModel(meta, []verifier.SourceResult{okResult()})
			out, err := Markdown{}.Render(m)
			if err != nil {
				t.Fatal(err)
			}
			got := string(out)
			for _, want := range tt.wants {
				if !strings.Contains(got, want) {
					t.Fatalf("rendered report missing %q\n---\n%s", want, got)
				}
			}
		})
	}
}

func TestMarkdownAnchorStatus(t *testing.T) {
	gen := time.Date(2026, 7, 4, 2, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		anchors    verifier.AnchorCheck
		wantSubs   []string
		absentSubs []string
	}{
		{
			name:    "not configured",
			anchors: verifier.AnchorCheck{},
			wantSubs: []string{
				"External timestamp anchor: **not configured** — checkpoint times rest on " +
					"agent clocks and verifier receipt order alone.",
			},
			absentSubs: []string{"Art. 41", "eIDAS-qualified"},
		},
		{
			name: "configured, not qualified",
			anchors: verifier.AnchorCheck{
				Total: 2, Matching: 2, Configured: true,
				TSA: "https://tsa.example/tsr", LatestGenTime: gen, Qualified: false,
			},
			wantSubs: []string{
				"External timestamp anchor: **2 anchor receipts** from `https://tsa.example/tsr`",
				"each receipt binds a checkpoint's exact bytes to an externally attested time.",
				"The TSA is not eIDAS-qualified: anchors prove existence-at-time but carry no " +
					"Art. 41 legal presumption.",
			},
		},
		{
			name: "configured, qualified drops the caveat",
			anchors: verifier.AnchorCheck{
				Total: 1, Matching: 1, Configured: true,
				TSA: "https://qtsa.example/tsr", LatestGenTime: gen, Qualified: true,
			},
			wantSubs: []string{
				"External timestamp anchor: **1 anchor receipt** from `https://qtsa.example/tsr`",
			},
			absentSubs: []string{"not eIDAS-qualified", "Art. 41 legal presumption"},
		},
		{
			// Honest-labeling tier (REQ-C-15): a stored anchor whose CMS signature
			// was not verified in-process must say so, and point to the external
			// `openssl ts -verify` check.
			name: "configured, token signature not verified in-process states the scope",
			anchors: verifier.AnchorCheck{
				Total: 1, Matching: 1, Configured: true,
				TSA: "https://tsa.example/tsr", LatestGenTime: gen,
				SignatureVerified: false,
			},
			wantSubs: []string{
				"each receipt's SHA-256 imprint and nonce round-trip are checked in-process",
				"the TSA token's CMS signature is **not** verified in-process",
				"verify externally with `openssl ts -verify`",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := okResult()
			r.Anchors = tt.anchors
			m := BuildModel(evidence.Meta{}, []verifier.SourceResult{r})
			out, err := Markdown{}.Render(m)
			if err != nil {
				t.Fatal(err)
			}
			got := string(out)
			for _, want := range tt.wantSubs {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q\n---\n%s", want, got)
				}
			}
			for _, absent := range tt.absentSubs {
				if strings.Contains(got, absent) {
					t.Fatalf("unexpected %q present\n---\n%s", absent, got)
				}
			}
		})
	}
}

func TestMarkdownNoFindings(t *testing.T) {
	m := BuildModel(evidence.Meta{}, []verifier.SourceResult{okResult()})
	out, err := Markdown{}.Render(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "No findings.") {
		t.Fatal("expected no-findings line")
	}
}

func TestMarkdownRetentionSection(t *testing.T) {
	// No expired segments: the §5.6 Retention section is omitted.
	m := BuildModel(evidence.Meta{}, []verifier.SourceResult{okResult()})
	out, err := Markdown{}.Render(m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "### 5.6 Retention") {
		t.Fatal("retention section should be omitted when nothing expired")
	}

	// Expired segments: the section renders with the range and roots-retained note.
	r := okResult()
	r.Retention = evidence.RetentionSummary{
		ExpiredSegments: 2, ExpiredRanges: []string{"seq 1-10", "seq 11-20"}, RootsRetained: true,
	}
	out, err = Markdown{}.Render(BuildModel(evidence.Meta{}, []verifier.SourceResult{r}))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(out)
	for _, want := range []string{"### 5.6 Retention", "2 segments expired", "seq 1-10", "verifiable-by-commitment"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("retention section missing %q", want)
		}
	}
}

func TestRendererInterface(_ *testing.T) {
	var _ Renderer = Markdown{}
}
