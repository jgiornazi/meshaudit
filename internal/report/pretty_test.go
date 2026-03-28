package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jgiornazi/meshaudit/internal/audit"
	"github.com/jgiornazi/meshaudit/internal/drift"
)

func TestPrintHeader_ContainsClusterAndNamespace(t *testing.T) {
	var buf bytes.Buffer
	PrintHeader(&buf, "v0.1.0", "my-cluster", "production")
	out := buf.String()
	if !strings.Contains(out, "my-cluster") {
		t.Errorf("expected cluster name in header, got: %q", out)
	}
	if !strings.Contains(out, "production") {
		t.Errorf("expected namespace in header, got: %q", out)
	}
}

func TestPrintMTLS_StrictService(t *testing.T) {
	var buf bytes.Buffer
	findings := []audit.MTLSFinding{
		{Service: "payments", Namespace: "production", Mode: audit.ModeStrict},
	}
	PrintMTLS(&buf, findings)
	out := buf.String()
	if !strings.Contains(out, "payments") {
		t.Errorf("expected service name in mTLS output, got: %q", out)
	}
	if !strings.Contains(out, "strict") {
		t.Errorf("expected 'strict' in mTLS output, got: %q", out)
	}
}

func TestPrintMTLS_PermissiveService_IncludesSuggestedFix(t *testing.T) {
	var buf bytes.Buffer
	findings := []audit.MTLSFinding{
		{
			Service:      "orders",
			Namespace:    "production",
			Mode:         audit.ModePermissive,
			SuggestedFix: "Set PeerAuthentication mode to STRICT",
		},
	}
	PrintMTLS(&buf, findings)
	out := buf.String()
	if !strings.Contains(out, "Set PeerAuthentication mode to STRICT") {
		t.Errorf("expected suggested fix in output, got: %q", out)
	}
}

func TestPrintAuthz_FailSeverity(t *testing.T) {
	var buf bytes.Buffer
	findings := []audit.AuthzFinding{
		{
			Policy:    "deny-all",
			Namespace: "production",
			Severity:  audit.SeverityFail,
			Detail:    "DENY policy has no workload selector",
		},
	}
	PrintAuthz(&buf, findings)
	out := buf.String()
	if !strings.Contains(out, "DENY policy has no workload selector") {
		t.Errorf("expected detail in authz output, got: %q", out)
	}
}

func TestPrintSummary_ScoreAndCounts(t *testing.T) {
	// 2 WARN authz = -10, score = 90
	mtls := []audit.MTLSFinding{
		{Service: "svc", Namespace: "ns", Mode: audit.ModeStrict},
	}
	authz := []audit.AuthzFinding{
		{Severity: audit.SeverityWarn},
		{Severity: audit.SeverityWarn},
	}
	var buf bytes.Buffer
	PrintSummary(&buf, mtls, authz)
	out := buf.String()
	if !strings.Contains(out, "90") {
		t.Errorf("expected score 90 in summary, got: %q", out)
	}
}

func TestModeStyle_AllBranches(t *testing.T) {
	tests := []audit.MTLSMode{
		audit.ModeStrict,
		audit.ModePermissive,
		audit.ModeDisabled,
		"UNKNOWN",
	}
	for _, mode := range tests {
		icon, label, c := modeStyle(mode)
		if icon == "" {
			t.Errorf("mode=%q: empty icon", mode)
		}
		if label == "" {
			t.Errorf("mode=%q: empty label", mode)
		}
		if c == nil {
			t.Errorf("mode=%q: nil color", mode)
		}
	}
}

func TestSeverityStyle_AllBranches(t *testing.T) {
	tests := []audit.AuthzSeverity{
		audit.SeverityFail,
		audit.SeverityWarn,
		audit.SeverityInfo,
	}
	for _, sev := range tests {
		icon, c := severityStyle(sev)
		if icon == "" {
			t.Errorf("sev=%q: empty icon", sev)
		}
		if c == nil {
			t.Errorf("sev=%q: nil color", sev)
		}
	}
}

func TestScoreColor_Bands(t *testing.T) {
	for _, score := range []int{95, 75, 50} {
		c := scoreColor(score)
		if c == nil {
			t.Errorf("scoreColor(%d) returned nil", score)
		}
	}
}

func TestPrintDrift_ContainsNameAndStatus(t *testing.T) {
	results := []drift.VSResult{
		{Name: "reviews-vs", Namespace: "production", Status: drift.StatusInSync},
		{Name: "ratings-vs", Namespace: "production", Status: drift.StatusDrifted, Diffs: []drift.FieldDiff{
			{Field: "spec.http", Live: "old", Desired: "new"},
		}},
		{Name: "old-vs", Namespace: "production", Status: drift.StatusLiveOnly},
		{Name: "new-vs", Namespace: "staging", Status: drift.StatusManifestOnly},
	}
	var buf bytes.Buffer
	PrintDrift(&buf, results)
	out := buf.String()

	for _, want := range []string{"reviews-vs", "ratings-vs", "old-vs", "new-vs", "spec.http"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in drift output, got: %q", want, out)
		}
	}
}

func TestDriftStyle_AllStatuses(t *testing.T) {
	statuses := []drift.DriftStatus{
		drift.StatusInSync,
		drift.StatusDrifted,
		drift.StatusLiveOnly,
		drift.StatusManifestOnly,
		"UNKNOWN",
	}
	for _, s := range statuses {
		icon, label, c := driftStyle(s)
		if icon == "" {
			t.Errorf("status=%q: empty icon", s)
		}
		if label == "" {
			t.Errorf("status=%q: empty label", s)
		}
		if c == nil {
			t.Errorf("status=%q: nil color", s)
		}
	}
}
