package audit

import (
	"context"
	"errors"
	"strings"
	"testing"

	istioapi "istio.io/api/security/v1beta1"
	istioapitype "istio.io/api/type/v1beta1"
	istioclientv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	istiofake "istio.io/client-go/pkg/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeAP(name, ns string, action istioapi.AuthorizationPolicy_Action, sel *istioapitype.WorkloadSelector, rules []*istioapi.Rule) *istioclientv1beta1.AuthorizationPolicy {
	return &istioclientv1beta1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: istioapi.AuthorizationPolicy{
			Selector: sel,
			Action:   action,
			Rules:    rules,
		},
	}
}

func selector(labels map[string]string) *istioapitype.WorkloadSelector {
	return &istioapitype.WorkloadSelector{MatchLabels: labels}
}

func fromPrincipals(principals ...string) *istioapi.Rule {
	return &istioapi.Rule{
		From: []*istioapi.Rule_From{
			{Source: &istioapi.Source{Principals: principals}},
		},
	}
}

func fromPrincipalsWithTo(principals []string, methods, paths []string) *istioapi.Rule {
	return &istioapi.Rule{
		From: []*istioapi.Rule_From{
			{Source: &istioapi.Source{Principals: principals}},
		},
		To: []*istioapi.Rule_To{
			{Operation: &istioapi.Operation{Methods: methods, Paths: paths}},
		},
	}
}

func hasSeverity(findings []AuthzFinding, sev AuthzSeverity) bool {
	for _, f := range findings {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

func hasDetail(findings []AuthzFinding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Detail, substr) {
			return true
		}
	}
	return false
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestAuthz_CleanPolicy_ReturnsInfo(t *testing.T) {
	ap := makeAP("clean", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "payments-svc"}),
		[]*istioapi.Rule{fromPrincipals("cluster.local/ns/default/sa/frontend")},
	)
	findings := evaluate(ap)
	if len(findings) != 1 || findings[0].Severity != SeverityInfo {
		t.Errorf("expected single INFO finding, got %+v", findings)
	}
}

func TestAuthz_WildcardPrincipal_ReturnsWarn(t *testing.T) {
	ap := makeAP("wildcard-principal", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "orders-svc"}),
		[]*istioapi.Rule{fromPrincipals("*")},
	)
	findings := evaluate(ap)
	if !hasSeverity(findings, SeverityWarn) {
		t.Error("expected WARN for wildcard principal, got none")
	}
	if !hasDetail(findings, "wildcard principal") {
		t.Error("expected 'wildcard principal' in detail")
	}
}

func TestAuthz_NoFromBlock_ReturnsWarn(t *testing.T) {
	ap := makeAP("no-from", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "cart-svc"}),
		[]*istioapi.Rule{{To: []*istioapi.Rule_To{{Operation: &istioapi.Operation{Methods: []string{"GET"}}}}}},
	)
	findings := evaluate(ap)
	if !hasSeverity(findings, SeverityWarn) {
		t.Error("expected WARN for missing from block, got none")
	}
	if !hasDetail(findings, "no 'from' principals") {
		t.Error("expected 'no from principals' in detail")
	}
}

func TestAuthz_WildcardMethod_WithWildcardPrincipal_ReturnsWarn(t *testing.T) {
	ap := makeAP("wildcard-method", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "api-svc"}),
		[]*istioapi.Rule{fromPrincipalsWithTo([]string{"*"}, []string{"*"}, nil)},
	)
	findings := evaluate(ap)
	warnCount := 0
	for _, f := range findings {
		if f.Severity == SeverityWarn {
			warnCount++
		}
	}
	if warnCount < 2 {
		t.Errorf("expected at least 2 WARNs (wildcard principal + wildcard method), got %d", warnCount)
	}
}

func TestAuthz_WildcardPath_WithBroadPrincipal_ReturnsWarn(t *testing.T) {
	ap := makeAP("wildcard-path", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "api-svc"}),
		[]*istioapi.Rule{fromPrincipalsWithTo([]string{"*"}, nil, []string{"/*"})},
	)
	findings := evaluate(ap)
	if !hasDetail(findings, "wildcard paths") {
		t.Error("expected 'wildcard paths' detail, got none")
	}
}

func TestAuthz_WildcardMethod_WithNarrowPrincipal_NoWildcardWarn(t *testing.T) {
	// Wildcard method is only flagged when paired with a broad principal.
	// Narrow principal + wildcard method should NOT fire the wildcard rule.
	ap := makeAP("narrow-principal-wildcard-method", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "api-svc"}),
		[]*istioapi.Rule{fromPrincipalsWithTo(
			[]string{"cluster.local/ns/default/sa/trusted"},
			[]string{"*"}, nil,
		)},
	)
	findings := evaluate(ap)
	for _, f := range findings {
		if f.Severity == SeverityWarn && strings.Contains(f.Detail, "wildcard methods") {
			t.Error("should not flag wildcard method when principal is narrow")
		}
	}
}

func TestAuthz_DenyNoSelector_ReturnsFail(t *testing.T) {
	ap := makeAP("deny-all", "production", istioapi.AuthorizationPolicy_DENY,
		nil, // no selector
		nil,
	)
	findings := evaluate(ap)
	if !hasSeverity(findings, SeverityFail) {
		t.Error("expected FAIL for DENY with no selector, got none")
	}
	if !hasDetail(findings, "DENY policy has no workload selector") {
		t.Error("expected DENY detail message")
	}
}

func TestAuthz_DenyWithSelector_NoFail(t *testing.T) {
	// DENY with a selector is legitimate — should not fire FAIL rule.
	ap := makeAP("deny-specific", "production", istioapi.AuthorizationPolicy_DENY,
		selector(map[string]string{"app": "admin-svc"}),
		[]*istioapi.Rule{fromPrincipals("cluster.local/ns/default/sa/frontend")},
	)
	findings := evaluate(ap)
	if hasSeverity(findings, SeverityFail) {
		t.Error("should not FAIL a DENY policy that has a selector")
	}
}

func TestAuthz_MultipleRulesFireIndependently(t *testing.T) {
	// One rule has a wildcard, another is clean — both should be evaluated.
	ap := makeAP("mixed-rules", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "mixed-svc"}),
		[]*istioapi.Rule{
			fromPrincipals("*"),
			fromPrincipals("cluster.local/ns/default/sa/safe"),
		},
	)
	findings := evaluate(ap)
	if !hasSeverity(findings, SeverityWarn) {
		t.Error("expected WARN from the wildcard rule")
	}
}

func TestAuthz_NilSourceInFrom_TreatedAsBroad(t *testing.T) {
	// Rule_From with a nil Source should be treated as broad (no principal scope).
	ap := makeAP("nil-source", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "svc"}),
		[]*istioapi.Rule{
			{
				From: []*istioapi.Rule_From{{Source: nil}},
				To:   []*istioapi.Rule_To{{Operation: &istioapi.Operation{Methods: []string{"*"}}}},
			},
		},
	)
	findings := evaluate(ap)
	// nil Source counts as broad, so wildcard method+broad principal should fire.
	if !hasSeverity(findings, SeverityWarn) {
		t.Error("expected WARN when Source is nil (treated as broad principal scope)")
	}
}

func TestAuthz_SelectorName_NonAppLabel(t *testing.T) {
	sel := &istioapitype.WorkloadSelector{
		MatchLabels: map[string]string{"version": "v2"},
	}
	name := selectorName(sel)
	if name != "v2" {
		t.Errorf("expected 'v2' from non-app label fallback, got %q", name)
	}
}

func TestAuthz_SelectorName_EmptyLabels(t *testing.T) {
	sel := &istioapitype.WorkloadSelector{MatchLabels: map[string]string{}}
	name := selectorName(sel)
	if name != "" {
		t.Errorf("expected empty string for empty labels, got %q", name)
	}
}

func TestScanAuthz_ViaFakeClient(t *testing.T) {
	ap := makeAP("wildcard", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "orders-svc"}),
		[]*istioapi.Rule{fromPrincipals("*")},
	)

	fakeClient := istiofake.NewSimpleClientset([]runtime.Object{ap}...)
	findings, err := ScanAuthz(context.Background(), fakeClient, []string{"production"})
	if err != nil {
		t.Fatalf("ScanAuthz returned error: %v", err)
	}
	if !hasSeverity(findings, SeverityWarn) {
		t.Error("expected WARN finding from fake client scan")
	}
}

func TestScanAuthz_EmptyNamespace_NoFindings(t *testing.T) {
	fakeClient := istiofake.NewSimpleClientset()
	findings, err := ScanAuthz(context.Background(), fakeClient, []string{"empty-ns"})
	if err != nil {
		t.Fatalf("ScanAuthz returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty namespace, got %d", len(findings))
	}
}

func TestAuthz_NilOperation_InTo_IsSkipped(t *testing.T) {
	// Rule.To with nil Operation should be skipped without panicking.
	ap := makeAP("nil-op", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "svc"}),
		[]*istioapi.Rule{
			{
				From: []*istioapi.Rule_From{
					{Source: &istioapi.Source{Principals: []string{"cluster.local/ns/default/sa/x"}}},
				},
				To: []*istioapi.Rule_To{{Operation: nil}},
			},
		},
	)
	findings := evaluate(ap)
	// No wildcard fired — should be INFO.
	if !hasSeverity(findings, SeverityInfo) {
		t.Error("expected INFO when To.Operation is nil")
	}
}

func TestAuthz_EmptyPrincipals_NonBroad(t *testing.T) {
	// Source with an empty Principals slice is not a wildcard — ruleHasBroadPrincipals returns false.
	ap := makeAP("empty-principals", "production", istioapi.AuthorizationPolicy_ALLOW,
		selector(map[string]string{"app": "svc"}),
		[]*istioapi.Rule{
			{
				From: []*istioapi.Rule_From{
					{Source: &istioapi.Source{Principals: []string{}}},
				},
				To: []*istioapi.Rule_To{
					{Operation: &istioapi.Operation{Methods: []string{"*"}}},
				},
			},
		},
	)
	findings := evaluate(ap)
	// Wildcard method but empty (non-wildcard) principals — should NOT fire the wildcard method+path rule.
	for _, f := range findings {
		if f.Severity == SeverityWarn && strings.Contains(f.Detail, "wildcard") {
			t.Error("should not flag wildcard method when principals list is empty (not a wildcard)")
		}
	}
}

func TestAuthz_SelectorName_NilPointer_ReturnsEmpty(t *testing.T) {
	// Passing a nil *WorkloadSelector — proto getter handles nil receiver safely.
	name := selectorName((*istioapitype.WorkloadSelector)(nil))
	if name != "" {
		t.Errorf("expected empty for nil pointer selector, got %q", name)
	}
}

func TestRuleHasBroadPrincipals_EmptyFrom(t *testing.T) {
	// Direct white-box test of the defensive empty-From branch.
	rule := &istioapi.Rule{From: nil}
	if !ruleHasBroadPrincipals(rule) {
		t.Error("empty From should be treated as broad")
	}
}

func TestScanAuthz_NonForbiddenError_Propagates(t *testing.T) {
	fakeClient := istiofake.NewSimpleClientset()
	fakeClient.PrependReactor("list", "authorizationpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	_, err := ScanAuthz(context.Background(), fakeClient, []string{"production"})
	if err == nil {
		t.Error("expected error to propagate from fake client, got nil")
	}
}
