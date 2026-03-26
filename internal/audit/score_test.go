package audit

import (
	"testing"
)

func TestScore_AllStrict_Clean_Is100(t *testing.T) {
	mtls := []MTLSFinding{
		{Mode: ModeStrict},
		{Mode: ModeStrict},
	}
	authz := []AuthzFinding{
		{Severity: SeverityInfo},
	}
	r := Compute(mtls, authz)
	if r.Score != 100 {
		t.Errorf("expected 100, got %d", r.Score)
	}
	if r.Band != BandGood {
		t.Errorf("expected GOOD, got %s", r.Band)
	}
}

func TestScore_OneDisabled_Deducts20(t *testing.T) {
	mtls := []MTLSFinding{{Mode: ModeDisabled}}
	r := Compute(mtls, nil)
	if r.Score != 80 {
		t.Errorf("expected 80, got %d", r.Score)
	}
}

func TestScore_OnePermissive_Deducts10(t *testing.T) {
	mtls := []MTLSFinding{{Mode: ModePermissive}}
	r := Compute(mtls, nil)
	if r.Score != 90 {
		t.Errorf("expected 90, got %d", r.Score)
	}
}

func TestScore_AuthzWarn_Deducts5(t *testing.T) {
	authz := []AuthzFinding{{Severity: SeverityWarn}}
	r := Compute(nil, authz)
	if r.Score != 95 {
		t.Errorf("expected 95, got %d", r.Score)
	}
}

func TestScore_AuthzFail_Deducts15(t *testing.T) {
	authz := []AuthzFinding{{Severity: SeverityFail}}
	r := Compute(nil, authz)
	if r.Score != 85 {
		t.Errorf("expected 85, got %d", r.Score)
	}
}

func TestScore_FullFormula(t *testing.T) {
	// From PRD example: 2 PASS, 1 PERMISSIVE, 1 DISABLED, 2 AUTHZ_WARN, 1 AUTHZ_FAIL
	// Score = 100 - 20 - 10 - (2×5) - 15 = 100 - 20 - 10 - 10 - 15 = 45
	mtls := []MTLSFinding{
		{Mode: ModeStrict},
		{Mode: ModeStrict},
		{Mode: ModePermissive},
		{Mode: ModeDisabled},
	}
	authz := []AuthzFinding{
		{Severity: SeverityWarn},
		{Severity: SeverityWarn},
		{Severity: SeverityFail},
	}
	r := Compute(mtls, authz)
	if r.Score != 45 {
		t.Errorf("expected 45, got %d", r.Score)
	}
	if r.Band != BandPoor {
		t.Errorf("expected POOR, got %s", r.Band)
	}
}

func TestScore_FloorAtZero(t *testing.T) {
	mtls := []MTLSFinding{
		{Mode: ModeDisabled},
		{Mode: ModeDisabled},
		{Mode: ModeDisabled},
		{Mode: ModeDisabled},
		{Mode: ModeDisabled},
		{Mode: ModeDisabled},
	}
	r := Compute(mtls, nil)
	if r.Score != 0 {
		t.Errorf("expected 0 (floor), got %d", r.Score)
	}
}

func TestScore_BandBoundaries(t *testing.T) {
	tests := []struct {
		score    int
		wantBand ScoreBand
	}{
		{100, BandGood},
		{90, BandGood},
		{89, BandFair},
		{70, BandFair},
		{69, BandPoor},
		{0, BandPoor},
	}
	for _, tt := range tests {
		got := band(tt.score)
		if got != tt.wantBand {
			t.Errorf("band(%d) = %s, want %s", tt.score, got, tt.wantBand)
		}
	}
}

func TestSummary_CountsCorrectly(t *testing.T) {
	mtls := []MTLSFinding{
		{Mode: ModeStrict},
		{Mode: ModePermissive},
		{Mode: ModeDisabled},
	}
	authz := []AuthzFinding{
		{Severity: SeverityInfo},
		{Severity: SeverityWarn},
		{Severity: SeverityFail},
	}
	pass, warn, fail := Summary(mtls, authz)
	if pass != 2 { // ModeStrict + SeverityInfo
		t.Errorf("expected 2 pass, got %d", pass)
	}
	if warn != 2 { // ModePermissive + SeverityWarn
		t.Errorf("expected 2 warn, got %d", warn)
	}
	if fail != 2 { // ModeDisabled + SeverityFail
		t.Errorf("expected 2 fail, got %d", fail)
	}
}
