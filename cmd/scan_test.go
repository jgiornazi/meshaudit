package cmd

import (
	"strings"
	"testing"
)

func TestRunScan_InvalidOutputFormat(t *testing.T) {
	orig := output
	t.Cleanup(func() { output = orig })
	output = "xml"
	err := runScan(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("expected 'unknown output format' error, got %v", err)
	}
}

func TestCheckThresholds_MinScore(t *testing.T) {
	err := checkThresholds(60, 80, false, 0, 0)
	if err != errFindings {
		t.Errorf("expected errFindings when score below minScore, got %v", err)
	}
}

func TestCheckThresholds_FailOnWarn(t *testing.T) {
	err := checkThresholds(100, 0, true, 1, 0)
	if err != errFindings {
		t.Errorf("expected errFindings when failOnWarn and warn>0, got %v", err)
	}
}

func TestCheckThresholds_Clean(t *testing.T) {
	err := checkThresholds(100, 0, false, 0, 0)
	if err != nil {
		t.Errorf("expected nil for clean result, got %v", err)
	}
}

func TestCheckThresholds_MinScoreZeroDisabled(t *testing.T) {
	// minScore=0 must never trigger regardless of score.
	err := checkThresholds(0, 0, false, 0, 0)
	if err != nil {
		t.Errorf("expected nil when minScore=0, got %v", err)
	}
}
