// Package report builds the continuity/integrity report model from verifier
// results and renders it. Markdown is the v1 renderer; framework projections
// implement the same Renderer interface (REQ-E-01, REQ-E-10).
package report

import (
	"github.com/arhuman/prooflog/internal/evidence"
	"github.com/arhuman/prooflog/internal/verifier"
)

// Renderer turns a report model into a document (REQ-E-10).
type Renderer interface {
	Render(m evidence.ReportModel) ([]byte, error)
}

// algorithms is the fixed set of algorithm identities every report is computed
// with, each citable to its defining standard (§5.5, REQ-E-02).
var algorithms = []string{
	"SHA-256 (FIPS 180-4)",
	"Ed25519 (RFC 8032 / FIPS 186-5)",
	"RFC 6962 §2.1 Merkle tree",
	"C2SP signed-note / tlog-checkpoint",
	"age X25519 + ChaCha20-Poly1305 (RFC 8439)",
}

// BuildModel projects verifier results into the render-ready report model
// (REQ-E-01). Findings from every source are surfaced per source.
func BuildModel(meta evidence.Meta, results []verifier.SourceResult) evidence.ReportModel {
	if meta.Schema == "" {
		meta.Schema = "prooflog.report/v1"
	}
	if len(meta.Algorithms) == 0 {
		meta.Algorithms = algorithms
	}
	sources := make([]evidence.SourceReport, 0, len(results))
	for _, r := range results {
		sources = append(sources, buildSource(r))
	}
	return evidence.ReportModel{Meta: meta, Sources: sources}
}

func buildSource(r verifier.SourceResult) evidence.SourceReport {
	integrityValid := r.Chain.Valid && r.Checkpoints.Consistent &&
		r.Checkpoints.RootsValid == r.Checkpoints.SignaturesValid &&
		r.Checkpoints.SignaturesValid == r.Checkpoints.Total

	unbounded := 0
	for _, w := range r.Continuity.Windows {
		if !w.Bounded {
			unbounded++
		}
	}

	sr := evidence.SourceReport{
		SourceID:      r.SourceID,
		Observability: observability(unbounded, r.Continuity.Summary.WithinPolicy),
		EventLoss:     eventLoss(r),
		Integrity:     boolText(integrityValid, "Valid", "INVALID"),
		Continuity: evidence.ContinuitySummary{
			IntervalSeconds: r.Continuity.Summary.IntervalSeconds,
			MaxSilence:      r.Continuity.Summary.MaxSilence,
			Expected:        r.Continuity.Summary.Expected,
			Observed:        r.Continuity.Summary.Observed,
			LongestGap:      r.Continuity.Summary.LongestGap,
			WithinPolicy:    r.Continuity.Summary.WithinPolicy,
		},
		Transport: evidence.TransportSummary{
			Outages:         r.Transport.Outages,
			LongestOutage:   r.Transport.LongestOutage,
			BufferedEvents:  r.Transport.BufferedEvents,
			ReplayCompleted: r.Transport.ReplayCompleted,
		},
		IntegrityData: evidence.IntegritySummary{
			SeqFirst:          r.SeqFirst,
			SeqLast:           r.SeqLast,
			SequenceGaps:      !r.Chain.Valid,
			ChainValid:        r.Chain.Valid,
			CheckpointsTotal:  r.Checkpoints.Total,
			CheckpointsValid:  r.Checkpoints.RootsValid,
			SignaturesValid:   r.Checkpoints.Total == r.Checkpoints.SignaturesValid,
			MaxClockDriftMS:   r.MaxClockDriftMS,
			ClockWithinPolicy: true,
		},
		Findings:          r.Findings,
		ChainHead:         r.ChainHead,
		EncryptedPayloads: r.Encrypted,
		KeyID:             r.KeyID,
		EventCounts:       r.EventCounts,
		Windows:           mapWindows(r.Continuity.Windows),
		Inputs:            r.Inputs,
		Anchors: evidence.AnchorSummary{
			Configured:                 r.Anchors.Configured,
			Total:                      r.Anchors.Total,
			Matching:                   r.Anchors.Matching,
			TSA:                        r.Anchors.TSA,
			LatestGenTime:              r.Anchors.LatestGenTime,
			Qualified:                  r.Anchors.Qualified,
			SignatureVerifiedInProcess: r.Anchors.SignatureVerified,
		},
		Retention: r.Retention,
	}
	sr.Status = status(integrityValid, unbounded, r.Continuity.Summary.WithinPolicy)
	return sr
}

// mapWindows projects verifier observation windows into the render model,
// keeping report free of transport/verifier internals (§3, REQ-E-06).
func mapWindows(ws []verifier.Window) []evidence.ObsWindow {
	if len(ws) == 0 {
		return nil
	}
	out := make([]evidence.ObsWindow, 0, len(ws))
	for _, w := range ws {
		out = append(out, evidence.ObsWindow{
			Start: w.Start, End: w.End, Duration: w.Duration, Bounded: w.Bounded,
		})
	}
	return out
}

func observability(unbounded int, withinPolicy bool) string {
	if unbounded == 0 && withinPolicy {
		return "Continuous"
	}
	if unbounded == 1 {
		return "1 unobserved window"
	}
	return plural(unbounded, "unobserved window")
}

func eventLoss(r verifier.SourceResult) string {
	if r.Chain.Valid {
		return "None"
	}
	return "Detected"
}

func status(integrityValid bool, unbounded int, withinPolicy bool) string {
	if integrityValid && unbounded == 0 && withinPolicy {
		return "OK"
	}
	if !integrityValid {
		return "FAIL"
	}
	return "ATTENTION"
}

func boolText(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}
