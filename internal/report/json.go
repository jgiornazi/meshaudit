package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/jgiornazi/meshaudit/internal/audit"
)

// Report is the top-level JSON output struct — matches the PRD schema (§10.3).
type Report struct {
	Cluster    string          `json:"cluster"`
	ScannedAt  string          `json:"scanned_at"`
	Namespace  string          `json:"namespace"`
	Score      int             `json:"score"`
	ScoreBand  string          `json:"score_band"`
	Summary    ReportSummary   `json:"summary"`
	Findings   []ReportFinding `json:"findings"`
}

// ReportSummary holds the pass/warn/fail counts.
type ReportSummary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// ReportFinding is a single normalised finding across mTLS and authz types.
type ReportFinding struct {
	Service      string `json:"service"`
	Namespace    string `json:"namespace"`
	Type         string `json:"type"`     // "mtls" or "authz"
	Severity     string `json:"severity"` // "PASS","WARN","FAIL","INFO"
	Detail       string `json:"detail"`
	SuggestedFix string `json:"suggested_fix,omitempty"`
}

// BuildReport assembles the full Report struct from scan results.
func BuildReport(cluster, namespace string, mtls []audit.MTLSFinding, authz []audit.AuthzFinding) Report {
	result := audit.Compute(mtls, authz)
	pass, warn, fail := audit.Summary(mtls, authz)

	var findings []ReportFinding

	for _, f := range mtls {
		sev, detail := mtlsSeverityDetail(f)
		findings = append(findings, ReportFinding{
			Service:      f.Service,
			Namespace:    f.Namespace,
			Type:         "mtls",
			Severity:     sev,
			Detail:       detail,
			SuggestedFix: f.SuggestedFix,
		})
	}

	for _, f := range authz {
		findings = append(findings, ReportFinding{
			Service:      f.Service,
			Namespace:    f.Namespace,
			Type:         "authz",
			Severity:     string(f.Severity),
			Detail:       f.Detail,
			SuggestedFix: f.SuggestedFix,
		})
	}

	return Report{
		Cluster:   cluster,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Namespace: namespace,
		Score:     result.Score,
		ScoreBand: string(result.Band),
		Summary:   ReportSummary{Pass: pass, Warn: warn, Fail: fail},
		Findings:  findings,
	}
}

// PrintJSON writes the report as indented JSON to w.
func PrintJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// mtlsSeverityDetail maps an mTLS finding to a severity string and detail message.
func mtlsSeverityDetail(f audit.MTLSFinding) (severity, detail string) {
	switch f.Mode {
	case audit.ModeStrict:
		return "PASS", "PeerAuthentication mode: STRICT"
	case audit.ModePermissive:
		return "WARN", "PeerAuthentication mode: PERMISSIVE"
	case audit.ModeDisabled:
		return "FAIL", "PeerAuthentication mode: DISABLED"
	default:
		return "INFO", string(f.Mode)
	}
}
