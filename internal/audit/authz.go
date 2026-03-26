package audit

import (
	"context"
	"fmt"
	"os"
	"strings"

	istioapi "istio.io/api/security/v1beta1"
	istioclientv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	istioclient "istio.io/client-go/pkg/clientset/versioned"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AuthzSeverity is the risk level of an AuthorizationPolicy finding.
type AuthzSeverity string

const (
	SeverityInfo AuthzSeverity = "INFO"
	SeverityWarn AuthzSeverity = "WARN"
	SeverityFail AuthzSeverity = "FAIL"
)

// AuthzFinding is the audit result for one AuthorizationPolicy.
type AuthzFinding struct {
	Policy       string // name of the AuthorizationPolicy resource
	Service      string // service the policy targets (empty = namespace/mesh-wide)
	Namespace    string
	Severity     AuthzSeverity
	Detail       string
	SuggestedFix string
}

// ScanAuthz fetches all AuthorizationPolicy resources across the given
// namespaces and applies the PRD risk rules to each one.
func ScanAuthz(ctx context.Context, istio istioclient.Interface, namespaces []string) ([]AuthzFinding, error) {
	var findings []AuthzFinding

	for _, ns := range namespaces {
		list, err := istio.SecurityV1beta1().AuthorizationPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			if k8serrors.IsForbidden(err) {
				authzRBACError(ns)
			}
			return nil, fmt.Errorf("list AuthorizationPolicies in %q: %w", ns, err)
		}
		for i := range list.Items {
			findings = append(findings, evaluate(list.Items[i])...)
		}
	}
	return findings, nil
}

// evaluate applies all risk rules to a single AuthorizationPolicy and returns
// one finding per triggered rule (or one INFO if none fire).
func evaluate(ap *istioclientv1beta1.AuthorizationPolicy) []AuthzFinding {
	var findings []AuthzFinding

	service := selectorName(ap.Spec.Selector)

	// Rule 1 — DENY with no workload selector silently blocks all namespace traffic.
	if ap.Spec.Action == istioapi.AuthorizationPolicy_DENY && ap.Spec.Selector == nil {
		findings = append(findings, AuthzFinding{
			Policy:       ap.Name,
			Service:      service,
			Namespace:    ap.Namespace,
			Severity:     SeverityFail,
			Detail:       "DENY policy has no workload selector — blocks all traffic in namespace",
			SuggestedFix: "Add a selector to scope the DENY policy to a specific workload",
		})
	}

	// Rules 2–4 — inspect each rule's from/to blocks.
	for _, rule := range ap.Spec.Rules {
		// Rule 2 — no from block at all: open to any caller.
		if len(rule.From) == 0 {
			findings = append(findings, AuthzFinding{
				Policy:       ap.Name,
				Service:      service,
				Namespace:    ap.Namespace,
				Severity:     SeverityWarn,
				Detail:       "AuthorizationPolicy has no 'from' principals — open to any caller in the mesh",
				SuggestedFix: "Add explicit service account principals to the 'from' block",
			})
			continue // skip further from-checks for this rule
		}

		for _, from := range rule.From {
			if from.Source == nil {
				continue
			}

			// Rule 3 — wildcard principal in from block.
			for _, p := range from.Source.Principals {
				if p == "*" {
					findings = append(findings, AuthzFinding{
						Policy:       ap.Name,
						Service:      service,
						Namespace:    ap.Namespace,
						Severity:     SeverityWarn,
						Detail:       "AuthorizationPolicy allows wildcard principal (*) — grants access to any mesh service",
						SuggestedFix: "Replace wildcard with explicit service account principals",
					})
				}
			}
		}

		// Rule 4 — wildcard method or path combined with broad (or no) principal scope.
		for _, to := range rule.To {
			if to.Operation == nil {
				continue
			}
			hasWildcardMethod := containsWildcard(to.Operation.Methods)
			hasWildcardPath := containsWildcard(to.Operation.Paths)
			if hasWildcardMethod || hasWildcardPath {
				// Only flag if principals are broad (wildcard or absent).
				if ruleHasBroadPrincipals(rule) {
					what := describeWildcards(hasWildcardMethod, hasWildcardPath)
					findings = append(findings, AuthzFinding{
						Policy:       ap.Name,
						Service:      service,
						Namespace:    ap.Namespace,
						Severity:     SeverityWarn,
						Detail:       fmt.Sprintf("AuthorizationPolicy allows %s with broad principal scope", what),
						SuggestedFix: "Restrict methods/paths to least-privilege routes or narrow the principal scope",
					})
				}
			}
		}
	}

	// If no rules fired, the policy is clean.
	if len(findings) == 0 {
		findings = append(findings, AuthzFinding{
			Policy:    ap.Name,
			Service:   service,
			Namespace: ap.Namespace,
			Severity:  SeverityInfo,
			Detail:    "AuthorizationPolicy present — no issues detected",
		})
	}
	return findings
}

// selectorName returns a human-readable workload name from a selector, or
// empty string for namespace/mesh-wide policies. Proto-generated getters are
// nil-safe so no explicit nil check is needed here.
func selectorName(sel interface{ GetMatchLabels() map[string]string }) string {
	labels := sel.GetMatchLabels()
	if app, ok := labels["app"]; ok {
		return app
	}
	// Fall back to first non-app label value (covers custom label selectors).
	// Returns "" when labels is empty.
	result := ""
	for _, v := range labels {
		result = v
		break
	}
	return result
}

// containsWildcard reports whether the slice contains a bare "*" or "/*".
func containsWildcard(vals []string) bool {
	for _, v := range vals {
		if v == "*" || v == "/*" {
			return true
		}
	}
	return false
}

// ruleHasBroadPrincipals returns true when the rule's from block is absent or
// contains a wildcard principal — i.e., not narrowly scoped.
func ruleHasBroadPrincipals(rule *istioapi.Rule) bool {
	if len(rule.From) == 0 {
		return true
	}
	for _, from := range rule.From {
		if from.Source == nil {
			return true
		}
		for _, p := range from.Source.Principals {
			if p == "*" {
				return true
			}
		}
	}
	return false
}

// describeWildcards builds a short label like "wildcard methods" or
// "wildcard methods and paths".
func describeWildcards(method, path bool) string {
	parts := []string{}
	if method {
		parts = append(parts, "wildcard methods")
	}
	if path {
		parts = append(parts, "wildcard paths")
	}
	return strings.Join(parts, " and ")
}

// authzRBACError prints a clear RBAC message and exits with code 2.
func authzRBACError(namespace string) {
	fmt.Fprintf(os.Stderr,
		"meshaudit error: permission denied listing AuthorizationPolicies in namespace %q.\n\n"+
			"Ensure the meshaudit-reader ClusterRole includes:\n"+
			"  - apiGroups: [\"security.istio.io\"]\n"+
			"    resources: [\"authorizationpolicies\"]\n"+
			"    verbs: [\"get\", \"list\"]\n", namespace)
	os.Exit(2)
}
