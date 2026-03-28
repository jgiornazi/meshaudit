package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/jgiornazi/meshaudit/internal/audit"
	"github.com/jgiornazi/meshaudit/internal/drift"
)

func TestBuildReport_Structure(t *testing.T) {
	mtls := []audit.MTLSFinding{
		{Service: "frontend", Namespace: "production", Mode: audit.ModeStrict},
		{Service: "backend", Namespace: "production", Mode: audit.ModePermissive, SuggestedFix: "set STRICT"},
	}
	authz := []audit.AuthzFinding{
		{Policy: "allow-frontend", Service: "frontend", Namespace: "production", Severity: audit.SeverityWarn, Detail: "wildcard principal"},
		{Policy: "deny-all", Service: "", Namespace: "production", Severity: audit.SeverityFail, Detail: "DENY policy has no workload selector"},
	}

	r := BuildReport("test-cluster", "production", mtls, authz)

	if r.Cluster != "test-cluster" {
		t.Errorf("Cluster=%q, want 'test-cluster'", r.Cluster)
	}
	if r.Namespace != "production" {
		t.Errorf("Namespace=%q, want 'production'", r.Namespace)
	}
	if r.Summary.Pass != 1 {
		t.Errorf("Summary.Pass=%d, want 1", r.Summary.Pass)
	}
	if r.Summary.Warn != 2 {
		t.Errorf("Summary.Warn=%d, want 2", r.Summary.Warn)
	}
	if r.Summary.Fail != 1 {
		t.Errorf("Summary.Fail=%d, want 1", r.Summary.Fail)
	}
	if len(r.Findings) != 4 {
		t.Errorf("len(Findings)=%d, want 4", len(r.Findings))
	}
	// Check type fields
	for _, f := range r.Findings[:2] {
		if f.Type != "mtls" {
			t.Errorf("expected type 'mtls', got %q", f.Type)
		}
	}
	for _, f := range r.Findings[2:] {
		if f.Type != "authz" {
			t.Errorf("expected type 'authz', got %q", f.Type)
		}
	}
}

func TestPrintJSON_Roundtrip(t *testing.T) {
	mtls := []audit.MTLSFinding{
		{Service: "svc", Namespace: "ns", Mode: audit.ModeStrict},
	}
	authz := []audit.AuthzFinding{
		{Policy: "pol", Service: "svc", Namespace: "ns", Severity: audit.SeverityInfo, Detail: "no issues"},
	}
	r := BuildReport("cluster", "ns", mtls, authz)

	var buf bytes.Buffer
	if err := PrintJSON(&buf, r); err != nil {
		t.Fatalf("PrintJSON error: %v", err)
	}

	var got Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if got.Cluster != r.Cluster {
		t.Errorf("Cluster: got %q, want %q", got.Cluster, r.Cluster)
	}
	if got.Score != r.Score {
		t.Errorf("Score: got %d, want %d", got.Score, r.Score)
	}
	if len(got.Findings) != len(r.Findings) {
		t.Errorf("Findings len: got %d, want %d", len(got.Findings), len(r.Findings))
	}
}

func TestBuildReport_RequiredJSONFields(t *testing.T) {
	mtls := []audit.MTLSFinding{
		{Service: "svc", Namespace: "ns", Mode: audit.ModeStrict},
	}
	authz := []audit.AuthzFinding{}

	r := BuildReport("my-cluster", "ns", mtls, authz)

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	required := []string{"cluster", "scanned_at", "namespace", "score", "score_band", "summary", "findings"}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required JSON field %q is missing", key)
		}
	}
}

func TestPrintDriftJSON_RequiredFields(t *testing.T) {
	results := []drift.VSResult{
		{Name: "reviews-vs", Namespace: "production", Status: drift.StatusInSync},
	}
	var buf bytes.Buffer
	err := PrintDriftJSON(&buf, "my-cluster", time.Now(), "production", results)
	if err != nil {
		t.Fatalf("PrintDriftJSON error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	required := []string{"cluster", "scanned_at", "namespace", "drift_results"}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required JSON field %q is missing", key)
		}
	}
}

func TestPrintDriftJSON_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	err := PrintDriftJSON(&buf, "cluster", time.Now(), "all", nil)
	if err != nil {
		t.Fatalf("PrintDriftJSON error: %v", err)
	}
	// Should emit an empty array, not null.
	if !bytes.Contains(buf.Bytes(), []byte(`"drift_results": []`)) {
		t.Errorf("expected empty array for drift_results, got: %s", buf.String())
	}
}

func TestMtlsSeverityDetail(t *testing.T) {
	tests := []struct {
		mode    audit.MTLSMode
		wantSev string
	}{
		{audit.ModeStrict, "PASS"},
		{audit.ModePermissive, "WARN"},
		{audit.ModeDisabled, "FAIL"},
		{"UNKNOWN", "INFO"},
	}
	for _, tt := range tests {
		f := audit.MTLSFinding{Mode: tt.mode}
		sev, _ := mtlsSeverityDetail(f)
		if sev != tt.wantSev {
			t.Errorf("mode=%q: got severity %q, want %q", tt.mode, sev, tt.wantSev)
		}
	}
}
