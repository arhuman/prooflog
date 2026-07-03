// Package assess runs prooflog's continuity analyzers over foreign, unsigned
// data (an export from another tool) to produce a Tier 0 "Evidence Assessment
// Report": analytical findings that are indicative, never cryptographically
// attested (ADR-0008). It shares no verifier internals: it consumes normalized
// records mapped from JSONL via a profile and folds them into a SourceResult
// whose findings carry A-* ids, distinct from the verifier's probative F-* ids.
package assess

import (
	"time"
)

// Record is one normalized unit of foreign data. Seq is a pointer because the
// absence of a sequence number is a capability fact (gap analysis is
// impossible), not a zero value. The raw source bytes are intentionally not
// retained here: they are hashed into the input digest at read time and dropped,
// so a large export does not cost ~2x its size in memory.
type Record struct {
	SourceID  string
	Seq       *uint64
	Time      time.Time
	Type      string
	Actor     string
	Heartbeat bool
}

// Capabilities declares which analyzers an input can support, derived
// mechanically from which profile mappings are present. It drives both analyzer
// selection and the report's honest disclosure of which analyses could not run.
type Capabilities struct {
	Sequenced  bool
	Heartbeats bool
	Typed      bool
	Actors     bool
}

// Missing returns human phrases for the analyses this input cannot support, for
// the report's "not assessable on this export" disclosure.
func (c Capabilities) Missing() []string {
	var out []string
	if !c.Sequenced {
		out = append(out, "sequence-gap and duplicate detection (no sequence field mapped)")
	}
	if !c.Heartbeats {
		out = append(out, "observation-gap detection (no heartbeat marker mapped)")
	}
	return out
}
