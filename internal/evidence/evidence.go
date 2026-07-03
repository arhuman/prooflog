// Package evidence holds the common report model: the continuity/integrity
// render model consumed by report renderers and the superset incident model
// whose per-framework reports are projections (REQ-R-01, REQ-E-01).
package evidence

import "time"

// Severity grades a finding.
type Severity string

// Finding severities.
const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Finding is a single verification observation surfaced in a report.
type Finding struct {
	ID             string
	Severity       Severity
	Title          string
	Detail         string
	Recommendation string
}

// Meta identifies a report and its provenance (REQ-E-02 chain of custody).
type Meta struct {
	ReportID     string
	Org          string
	PeriodStart  time.Time
	PeriodEnd    time.Time
	Generated    time.Time
	VerifierName string
	Schema       string

	// VerifierKeyID is the signing key id shown in the header/footer once the
	// report is signed; empty when the report is unsigned (REQ-E-10).
	VerifierKeyID string
	// VerifierOperator names the entity operating the verifier. Empty or equal
	// to the organization means a self-hosted anchor (SelfHosted) with no
	// separation of powers (decisions.md trust model).
	VerifierOperator string
	// SelfHosted is true when the verifier is not independent from the storage
	// operator; the report must state this honestly (REQ-E-01, REQ-E-08).
	SelfHosted bool
	// Reproduce is the exact `prooflog verify ...` command line that
	// re-verifies this report offline (REQ-E-10).
	Reproduce string

	// ToolVersion is the prooflog build that generated this report (REQ-E-02).
	ToolVersion string
	// VerifierBinaryHash is the SHA-256 hex of the running executable, or
	// "unavailable" when it cannot be read (REQ-E-02).
	VerifierBinaryHash string
	// Algorithms lists the exact algorithm identities used, each citable (§5.5).
	Algorithms []string

	// StoreLocality and VerifierLocality are operator-declared jurisdictions
	// (e.g. "CH", "EU/DE") recorded for chain-of-custody documentation.
	// They are declarations, not cryptographic proofs; the report says so.
	StoreLocality    string
	VerifierLocality string

	// Tier grades the assurance the report's findings carry (ADR-0008). The
	// continuity report derives it from the trust disclosure (DeriveTier); the
	// assess path sets it to TierAssessed explicitly.
	Tier AssuranceTier
	// DocumentTitle overrides the rendered report title. Empty means the
	// renderer's default ("Continuity & Integrity Report").
	DocumentTitle string
}

// InputAttestation pins exactly which evidence this report was computed from.
type InputAttestation struct {
	RecordCount   int
	InputDigest   string   // SHA-256 hex over the ordered per-record hashes
	CheckpointIDs []string // "origin@size root=<b64 first 12 chars>…" per accepted checkpoint
}

// EventCount is one row of the critical-events evidence summary: an event type
// and how many records of it were recorded, derived from visible envelope
// metadata only (payloads stay encrypted, REQ-E-01).
type EventCount struct {
	Type  string
	Count int
}

// ObsWindow is an observation window between heartbeats that exceeded the max
// allowed silence; Bounded means it was framed by clean agent stop/start
// events (REQ-E-06).
type ObsWindow struct {
	Start    time.Time
	End      time.Time
	Duration time.Duration
	Bounded  bool
}

// ContinuitySummary reports heartbeat-derived observability for one source.
type ContinuitySummary struct {
	IntervalSeconds int
	MaxSilence      time.Duration
	Expected        int
	Observed        int
	LongestGap      time.Duration
	WithinPolicy    bool
}

// TransportSummary reports outage tolerance for one source.
type TransportSummary struct {
	Outages         int
	LongestOutage   time.Duration
	BufferedEvents  uint64
	ReplayCompleted bool
}

// IntegritySummary reports cryptographic integrity for one source.
type IntegritySummary struct {
	SeqFirst          uint64
	SeqLast           uint64
	SequenceGaps      bool
	ChainValid        bool
	CheckpointsTotal  int
	CheckpointsValid  int
	SignaturesValid   bool
	MaxClockDriftMS   int64
	ClockWithinPolicy bool
}

// RetentionSummary reports segments expired (blob-deleted) under the retention
// policy for one source. Their roots and checkpoints are retained, so the range
// stays verifiable-by-commitment even though the ciphertext is gone (WS6).
type RetentionSummary struct {
	ExpiredSegments int
	ExpiredRanges   []string // "seq A-B" per tombstoned segment
	RootsRetained   bool     // every expired segment's root matches an accepted checkpoint
}

// AnchorSummary reports external RFC 3161 timestamp coverage for one source,
// as rendered in §5.3 (REQ-C-15).
type AnchorSummary struct {
	Configured    bool
	Total         int
	Matching      int
	TSA           string
	LatestGenTime time.Time
	Qualified     bool
	// SignatureVerifiedInProcess reports whether the TSA token's CMS signature
	// and certificate chain were cryptographically verified in-process. It is
	// false today: only the imprint and nonce round-trip are checked; the token
	// signature is externally verifiable via `openssl ts -verify` (REQ-C-15).
	SignatureVerifiedInProcess bool
}

// SourceReport is the per-source verdict block of a continuity report.
type SourceReport struct {
	SourceID      string
	Observability string
	EventLoss     string
	Integrity     string
	Status        string
	Continuity    ContinuitySummary
	Transport     TransportSummary
	IntegrityData IntegritySummary
	Findings      []Finding

	// ChainHead is the hex hash chain head at period end (§5.2).
	ChainHead string
	// EncryptedPayloads is true when business events on this source carry
	// client-side encrypted payloads (payload_ct); drives the privacy posture
	// (REQ-C-08, §7).
	EncryptedPayloads bool
	// KeyID is the organization recipient key id that holds decryption
	// authority for this source's payloads (§7 privacy posture).
	KeyID string
	// EventCounts summarizes recorded event types (heartbeats excluded, §6).
	EventCounts []EventCount
	// Windows lists observation windows breaching the max-silence policy (§3).
	Windows []ObsWindow
	// Inputs pins the exact evidence this source's verdict was computed from (§5.5).
	Inputs InputAttestation
	// Anchors summarizes external timestamp coverage for this source (§5.3).
	Anchors AnchorSummary
	// Retention summarizes segments expired under the retention policy (§5.6).
	Retention RetentionSummary
}

// ReportModel is the render-ready model passed to a Renderer (REQ-E-01).
type ReportModel struct {
	Meta     Meta
	Sources  []SourceReport
	Incident *Incident
}

// Provenance tags whether a report field was auto-populated from verified
// evidence or left as a manual operator input slot (REQ-R-01).
type Provenance string

// Field provenance values.
const (
	Auto   Provenance = "auto"
	Manual Provenance = "manual"
)

// Field is a report field tagged with its provenance and presence (REQ-R-01).
type Field[T any] struct {
	Value      T
	Provenance Provenance
	Present    bool
}

// AutoField builds an auto-populated field from verified evidence.
func AutoField[T any](v T) Field[T] {
	return Field[T]{Value: v, Provenance: Auto, Present: true}
}

// ManualSlot builds an empty manual-input field.
func ManualSlot[T any]() Field[T] {
	return Field[T]{Provenance: Manual}
}

// CIAImpact captures confidentiality/integrity/availability impact.
type CIAImpact struct {
	Confidentiality bool
	Integrity       bool
	Availability    bool
}

// Incident is the superset incident-evidence model; per-framework reports (NCSC,
// GDPR, NIS2, ...) are projections of it (REQ-R-01).
type Incident struct {
	Discovery       Field[time.Time]
	AttackType      Field[string]
	HowCarriedOut   Field[string]
	AffectedAssets  Field[[]string]
	Impact          Field[CIAImpact]
	Severity        Field[string]
	IoCs            Field[[]string]
	MeasuresTaken   Field[[]string]
	MeasuresPlanned Field[[]string]
	RootCause       Field[string]
	CrossBorder     Field[bool]
	UserImpact      Field[string]
	Contact         Field[string]
}
