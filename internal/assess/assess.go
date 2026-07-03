package assess

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/arhuman/prooflog/internal/evidence"
)

// Policy sets the continuity thresholds an assessment is evaluated against.
// Assess needs only heartbeat timing, so it defines its own Policy rather than
// depending on the verifier's (which also carries clock-drift limits an
// unsigned assessment cannot check) — keeping the assess package free of any
// verifier dependency.
type Policy struct {
	HeartbeatInterval time.Duration
	MaxSilence        time.Duration
}

// DefaultPolicy is the v1 assessment policy: 60s heartbeats, 3m max silence.
func DefaultPolicy() Policy {
	return Policy{HeartbeatInterval: 60 * time.Second, MaxSilence: 3 * time.Minute}
}

// Window bounds the reporting period an assessment is evaluated against. A zero
// Start or End disables the corresponding coverage check.
type Window struct {
	Start time.Time
	End   time.Time
}

// Analyzer thresholds, named rather than inline so their intent and tuning are
// explicit (§ review 2026-07-05, consistency).
const (
	// malformedRatioThreshold raises A-INPUT once malformed lines exceed this
	// fraction of the input.
	malformedRatioThreshold = 0.001
	// coverageSlack is how far inside the declared period the observed data may
	// start/end before A-COVERAGE flags a leading/trailing hole.
	coverageSlack = time.Hour
	// monotonicTolerance is how far a timestamp may decrease as sequence
	// increases before A-TIME counts it as non-monotonic.
	monotonicTolerance = time.Second
)

// SourceResult is the assessment of one source. It deliberately carries no
// chain/checkpoint/anchor fields: there is no attested capture to report, and a
// zero-valued integrity field must never read as "verified".
type SourceResult struct {
	SourceID    string
	Caps        Capabilities
	Records     int
	SeqFirst    uint64
	SeqLast     uint64
	TimeFirst   time.Time
	TimeLast    time.Time
	EventCounts []evidence.EventCount
	Windows     []evidence.ObsWindow
	Findings    []evidence.Finding
	Inputs      evidence.InputAttestation
}

// maxSampleRanges caps how many gap ranges a finding enumerates before
// summarizing, so a pathological export cannot produce an unbounded finding.
const maxSampleRanges = 20

// Assess folds one source's normalized records into a Tier 0 SourceResult,
// running only the analyzers its capabilities support. malformed is the count of
// unparseable input lines attributed to this input (reported as A-INPUT above a
// small threshold). Records are analyzed in input order; sequence and time
// analyses sort internally as needed. Findings are indicative, never attested,
// and carry A-* ids (REQ-E-16); the input digest binds them to exact bytes
// (REQ-E-15).
func Assess(si SourceInput, caps Capabilities, policy Policy, period Window, malformed int) SourceResult {
	res := SourceResult{
		SourceID: si.SourceID,
		Caps:     caps,
		Records:  len(si.Records),
		Inputs: evidence.InputAttestation{
			RecordCount: si.RawCount,
			InputDigest: si.Digest.Hex(),
		},
	}

	res.EventCounts = countTypes(si.Records)
	res.TimeFirst, res.TimeLast = timeSpan(si.Records)

	inputFindings(&res, len(si.Records), malformed)
	if caps.Sequenced {
		sequenceFindings(&res, si.Records)
	}
	if caps.Heartbeats {
		heartbeatFindings(&res, si.Records, policy)
	}
	timeFindings(&res, si.Records, caps.Sequenced, period)
	coverageFindings(&res, period)

	return res
}

func countTypes(records []Record) []evidence.EventCount {
	counts := map[string]int{}
	var order []string
	for _, r := range records {
		if r.Heartbeat {
			continue
		}
		t := r.Type
		if t == "" {
			t = "(untyped)"
		}
		if _, seen := counts[t]; !seen {
			order = append(order, t)
		}
		counts[t]++
	}
	sort.Strings(order)
	out := make([]evidence.EventCount, 0, len(order))
	for _, t := range order {
		out = append(out, evidence.EventCount{Type: t, Count: counts[t]})
	}
	return out
}

func timeSpan(records []Record) (first, last time.Time) {
	for _, r := range records {
		if r.Time.IsZero() {
			continue
		}
		if first.IsZero() || r.Time.Before(first) {
			first = r.Time
		}
		if last.IsZero() || r.Time.After(last) {
			last = r.Time
		}
	}
	return first, last
}

// inputFindings raises A-INPUT when malformed lines exceed 0.1% of the input, so
// a partially-corrupt export is disclosed rather than silently under-counted.
func inputFindings(res *SourceResult, parsed, malformed int) {
	if malformed == 0 {
		return
	}
	total := parsed + malformed
	if total == 0 {
		return
	}
	ratio := float64(malformed) / float64(total)
	if ratio < malformedRatioThreshold {
		return
	}
	res.Findings = append(res.Findings, evidence.Finding{
		ID:             "A-INPUT",
		Severity:       evidence.SeverityMedium,
		Title:          "malformed input lines",
		Detail:         fmt.Sprintf("%d of %d input lines (%.2f%%) could not be parsed and were excluded from analysis; the input digest still covers them.", malformed, total, ratio*100),
		Recommendation: "Re-export cleanly, or confirm the mapping profile matches the source shape.",
	})
}

// sequenceFindings raises A-SEQGAP (missing numbers) and A-DUP (repeated
// numbers) over the observed sequence range.
func sequenceFindings(res *SourceResult, records []Record) {
	seqs := make([]uint64, 0, len(records))
	seen := map[uint64]int{}
	for _, r := range records {
		if r.Seq == nil {
			continue
		}
		seqs = append(seqs, *r.Seq)
		seen[*r.Seq]++
	}
	if len(seqs) == 0 {
		return
	}
	slices.Sort(seqs)
	res.SeqFirst = seqs[0]
	res.SeqLast = seqs[len(seqs)-1]

	var gaps []string
	var missing uint64
	for i := 1; i < len(seqs); i++ {
		prev, cur := seqs[i-1], seqs[i]
		if cur <= prev+1 {
			continue
		}
		lo, hi := prev+1, cur-1
		missing += hi - lo + 1
		if len(gaps) < maxSampleRanges {
			gaps = append(gaps, rangeStr(lo, hi))
		}
	}
	if missing > 0 {
		detail := fmt.Sprintf("%d sequence number(s) missing between %d and %d: %s.",
			missing, res.SeqFirst, res.SeqLast, strings.Join(gaps, ", "))
		if uint64(len(gaps)) < missing && len(gaps) == maxSampleRanges {
			detail += " (ranges truncated)"
		}
		res.Findings = append(res.Findings, evidence.Finding{
			ID:             "A-SEQGAP",
			Severity:       evidence.SeverityHigh,
			Title:          "sequence gap in exported data",
			Detail:         detail + " Indicative only: these numbers are from an unsigned export and cannot be proven to have existed.",
			Recommendation: "Capture with a prooflog agent to make sequence continuity provable (Tier 1+).",
		})
	}

	var dups []string
	for _, s := range seqs {
		if seen[s] > 1 {
			if len(dups) < maxSampleRanges {
				dups = append(dups, fmt.Sprintf("%d×%d", seen[s], s))
			}
			seen[s] = 0
		}
	}
	if len(dups) > 0 {
		res.Findings = append(res.Findings, evidence.Finding{
			ID:             "A-DUP",
			Severity:       evidence.SeverityMedium,
			Title:          "duplicate sequence numbers",
			Detail:         "repeated sequence numbers (count×value): " + strings.Join(dups, ", ") + ". Often a double export or an upstream re-emission.",
			Recommendation: "De-duplicate the export, or confirm the source does not reuse sequence numbers.",
		})
	}
}

// heartbeatFindings derives observation windows from heartbeat records: a
// silence longer than the policy max is an unbounded window (foreign data has no
// clean stop/start events, so no window is ever Bounded).
func heartbeatFindings(res *SourceResult, records []Record, policy Policy) {
	var beats []time.Time
	for _, r := range records {
		if r.Heartbeat && !r.Time.IsZero() {
			beats = append(beats, r.Time)
		}
	}
	if len(beats) < 2 {
		return
	}
	sort.Slice(beats, func(i, j int) bool { return beats[i].Before(beats[j]) })

	interval := policy.HeartbeatInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	var longest time.Duration
	for i := 1; i < len(beats); i++ {
		gap := beats[i].Sub(beats[i-1])
		if gap > longest {
			longest = gap
		}
		if gap > policy.MaxSilence {
			res.Windows = append(res.Windows, evidence.ObsWindow{
				Start:    beats[i-1],
				End:      beats[i],
				Duration: gap,
				Bounded:  false,
			})
		}
	}
	if len(res.Windows) > 0 {
		res.Findings = append(res.Findings, evidence.Finding{
			ID:       "A-HBGAP",
			Severity: evidence.SeverityHigh,
			Title:    "observation gap between heartbeats",
			Detail: fmt.Sprintf("%d silence(s) exceeded the max-silence policy (%s); longest %s. Indicative: without signed heartbeats, a gap cannot be distinguished from a missing export.",
				len(res.Windows), fmtSpan(policy.MaxSilence), fmtSpan(longest)),
			Recommendation: "Signed heartbeats from a prooflog agent turn these into provable liveness windows.",
		})
	}
}

// timeFindings raises A-TIME for timestamps that are unparseable (zero), out of
// the declared period, or non-monotonic in sequence order.
func timeFindings(res *SourceResult, records []Record, sequenced bool, period Window) {
	var zero, outOfPeriod, nonMono int
	for _, r := range records {
		if r.Time.IsZero() {
			zero++
			continue
		}
		if !period.Start.IsZero() && r.Time.Before(period.Start) {
			outOfPeriod++
		}
		if !period.End.IsZero() && r.Time.After(period.End) {
			outOfPeriod++
		}
	}
	if sequenced {
		ordered := append([]Record(nil), records...)
		sort.SliceStable(ordered, func(i, j int) bool {
			if ordered[i].Seq == nil || ordered[j].Seq == nil {
				return false
			}
			return *ordered[i].Seq < *ordered[j].Seq
		})
		var prev time.Time
		for _, r := range ordered {
			if r.Seq == nil || r.Time.IsZero() {
				continue
			}
			if !prev.IsZero() && r.Time.Before(prev.Add(-monotonicTolerance)) {
				nonMono++
			}
			prev = r.Time
		}
	}
	if zero+outOfPeriod+nonMono == 0 {
		return
	}
	var parts []string
	if zero > 0 {
		parts = append(parts, fmt.Sprintf("%d record(s) with an unparseable/absent timestamp", zero))
	}
	if outOfPeriod > 0 {
		parts = append(parts, fmt.Sprintf("%d record(s) outside the declared period", outOfPeriod))
	}
	if nonMono > 0 {
		parts = append(parts, fmt.Sprintf("%d record(s) whose time decreases as sequence increases", nonMono))
	}
	res.Findings = append(res.Findings, evidence.Finding{
		ID:             "A-TIME",
		Severity:       evidence.SeverityLow,
		Title:          "timestamp anomalies",
		Detail:         strings.Join(parts, "; ") + ".",
		Recommendation: "Confirm the timestamp field and layout in the profile, and the source's clock discipline.",
	})
}

// coverageFindings raises A-COVERAGE when the observed time span does not cover
// the declared reporting period, stating the leading/trailing holes explicitly.
func coverageFindings(res *SourceResult, period Window) {
	if period.Start.IsZero() && period.End.IsZero() {
		return
	}
	if res.TimeFirst.IsZero() {
		return
	}
	var parts []string
	if !period.Start.IsZero() && res.TimeFirst.After(period.Start.Add(coverageSlack)) {
		parts = append(parts, fmt.Sprintf("no data for the first %s of the period (starts %s, period opens %s)",
			fmtSpan(res.TimeFirst.Sub(period.Start)), fmtDate(res.TimeFirst), fmtDate(period.Start)))
	}
	if !period.End.IsZero() && res.TimeLast.Before(period.End.Add(-coverageSlack)) {
		parts = append(parts, fmt.Sprintf("no data for the last %s of the period (ends %s, period closes %s)",
			fmtSpan(period.End.Sub(res.TimeLast)), fmtDate(res.TimeLast), fmtDate(period.End)))
	}
	if len(parts) == 0 {
		return
	}
	res.Findings = append(res.Findings, evidence.Finding{
		ID:             "A-COVERAGE",
		Severity:       evidence.SeverityMedium,
		Title:          "export does not cover the full period",
		Detail:         "the export's observed range does not span the requested period: " + strings.Join(parts, "; ") + ".",
		Recommendation: "Widen the export window, or narrow --period to the range the export actually covers.",
	})
}

func rangeStr(lo, hi uint64) string {
	if lo == hi {
		return fmt.Sprintf("%d", lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

func fmtDate(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02")
}

// fmtSpan formats an observation span or gap, scaling up to days. Named apart
// from report/markdown.go's fmtDur, which caps at minutes for its own output.
func fmtSpan(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(d/time.Minute), int((d%time.Minute)/time.Second))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int((d%time.Hour)/time.Minute))
	}
	return fmt.Sprintf("%dd%02dh", int(d/(24*time.Hour)), int((d%(24*time.Hour))/time.Hour))
}
