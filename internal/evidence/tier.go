package evidence

// AssuranceTier grades how much cryptographic assurance a report's findings
// carry, from analytical-only to independently witnessed. It is the single
// honest scale stated in every report header (ADR-0008); a Tier 0 assessment
// must never be mistaken for a captured/verified report.
type AssuranceTier int

// Assurance tiers, lowest to highest.
const (
	// TierAssessed (0): findings computed over foreign, unsigned data
	// (an export from another tool). Analytical only — nothing is attested.
	TierAssessed AssuranceTier = iota
	// TierCaptured (1): evidence captured by a prooflog agent but verified by
	// a self-hosted anchor with no separation of powers (SelfHosted).
	TierCaptured
	// TierVerified (2): evidence verified by an anchor independent of the
	// store operator.
	TierVerified
	// TierWitnessed (3): independently verified and additionally witnessed by
	// an external cosigner or a qualified timestamp anchor. Reserved for the
	// witness/qualified-TSA roadmap (ADR-0008); the derivation rule lands
	// with those features.
	TierWitnessed
)

// String returns the short machine-ish tier token.
func (t AssuranceTier) String() string {
	switch t {
	case TierAssessed:
		return "assessed"
	case TierCaptured:
		return "captured"
	case TierVerified:
		return "verified"
	case TierWitnessed:
		return "witnessed"
	default:
		return "unknown"
	}
}

// Label returns the human phrase shown in a report header.
func (t AssuranceTier) Label() string {
	switch t {
	case TierAssessed:
		return "Tier 0 — assessed (analytical only; no finding cryptographically attested)"
	case TierCaptured:
		return "Tier 1 — captured (single administrative domain; not independently verified)"
	case TierVerified:
		return "Tier 2 — independently verified"
	case TierWitnessed:
		return "Tier 3 — independently verified and externally witnessed"
	default:
		return "unknown tier"
	}
}

// DeriveTier maps a report's existing trust disclosure onto the tier ladder for
// captured evidence. It never returns TierAssessed: that tier is set explicitly
// by the assess path, which builds its own model. A self-hosted verifier is
// Tier 1; an independent operator is Tier 2. Tier 3 is not derived here — it is
// set when witness/qualified-anchor evidence is present.
func DeriveTier(m Meta) AssuranceTier {
	if m.SelfHosted || m.VerifierOperator == "" || m.VerifierOperator == m.Org {
		return TierCaptured
	}
	return TierVerified
}
