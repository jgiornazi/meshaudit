package audit

// ScoreBand classifies the numeric posture score into a human-readable tier.
type ScoreBand string

const (
	BandGood ScoreBand = "GOOD"
	BandFair ScoreBand = "FAIR"
	BandPoor ScoreBand = "POOR"
)

// ScoreResult holds the computed posture score and its band.
type ScoreResult struct {
	Score int
	Band  ScoreBand
}

// Compute calculates the 0–100 posture score from both mTLS and authz findings
// using the PRD weighted formula:
//
//	Score = 100 − (DISABLED×20) − (PERMISSIVE×10) − (AUTHZ_WARN×5) − (AUTHZ_FAIL×15)
func Compute(mtls []MTLSFinding, authz []AuthzFinding) ScoreResult {
	score := 100

	for _, f := range mtls {
		switch f.Mode {
		case ModeDisabled:
			score -= 20
		case ModePermissive:
			score -= 10
		}
	}

	for _, f := range authz {
		switch f.Severity {
		case SeverityWarn:
			score -= 5
		case SeverityFail:
			score -= 15
		}
	}

	if score < 0 {
		score = 0
	}

	return ScoreResult{Score: score, Band: band(score)}
}

// Summary counts PASS / WARN / FAIL across both finding types.
func Summary(mtls []MTLSFinding, authz []AuthzFinding) (pass, warn, fail int) {
	for _, f := range mtls {
		switch f.Mode {
		case ModeStrict:
			pass++
		case ModePermissive:
			warn++
		case ModeDisabled:
			fail++
		}
	}
	for _, f := range authz {
		switch f.Severity {
		case SeverityInfo:
			pass++
		case SeverityWarn:
			warn++
		case SeverityFail:
			fail++
		}
	}
	return
}

func band(score int) ScoreBand {
	switch {
	case score >= 90:
		return BandGood
	case score >= 70:
		return BandFair
	default:
		return BandPoor
	}
}
