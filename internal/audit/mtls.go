package audit

import (
	"context"
	"fmt"

	istioapi "istio.io/api/security/v1beta1"
	istioclientv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	istioclient "istio.io/client-go/pkg/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jgiornazi/meshaudit/internal/k8s"
)

// MTLSMode is the resolved mTLS posture for a single service.
type MTLSMode string

const (
	ModeStrict     MTLSMode = "STRICT"
	ModePermissive MTLSMode = "PERMISSIVE"
	ModeDisabled   MTLSMode = "DISABLED"
)

// MTLSFinding is the audit result for one service.
type MTLSFinding struct {
	Service      string
	Namespace    string
	Mode         MTLSMode
	SuggestedFix string // empty when Mode == ModeStrict
}

// paStore holds all PeerAuthentication resources partitioned by scope so the
// resolver can quickly find the right policy for each service.
type paStore struct {
	// meshWide is at most one PA: namespace=istio-system, no selector.
	meshWide *istioclientv1beta1.PeerAuthentication

	// namespacePolicies maps namespace → the namespace-scoped PA (no selector).
	// Only the first match per namespace is kept; multiple namespace-scoped PAs
	// in the same namespace is a misconfiguration Istio itself warns about.
	namespacePolicies map[string]*istioclientv1beta1.PeerAuthentication

	// workloadPolicies maps namespace → slice of workload-scoped PAs (have selector).
	workloadPolicies map[string][]*istioclientv1beta1.PeerAuthentication
}

// ScanMTLS fetches all PeerAuthentication resources and resolves the effective
// mTLS mode for each service using Istio's precedence rules:
//
//	workload-scoped > namespace-scoped > mesh-wide > default (PERMISSIVE)
func ScanMTLS(ctx context.Context, istio istioclient.Interface, services []k8s.Service) ([]MTLSFinding, error) {
	// List PeerAuthentications across all namespaces in a single API call.
	paList, err := istio.SecurityV1beta1().PeerAuthentications("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list PeerAuthentications: %w", err)
	}

	store := buildPAStore(paList.Items)

	findings := make([]MTLSFinding, 0, len(services))
	for _, svc := range services {
		mode := store.resolve(svc)
		findings = append(findings, MTLSFinding{
			Service:      svc.Name,
			Namespace:    svc.Namespace,
			Mode:         mode,
			SuggestedFix: suggestedFix(mode),
		})
	}
	return findings, nil
}

// buildPAStore partitions a flat list of PeerAuthentications into the three
// scope buckets used by the resolver.
func buildPAStore(items []*istioclientv1beta1.PeerAuthentication) paStore {
	store := paStore{
		namespacePolicies: make(map[string]*istioclientv1beta1.PeerAuthentication),
		workloadPolicies:  make(map[string][]*istioclientv1beta1.PeerAuthentication),
	}

	for _, pa := range items {
		hasSelector := pa.Spec.Selector != nil && len(pa.Spec.Selector.MatchLabels) > 0

		if hasSelector {
			ns := pa.Namespace
			store.workloadPolicies[ns] = append(store.workloadPolicies[ns], pa)
			continue
		}

		// No selector: either mesh-wide or namespace-scoped.
		if pa.Namespace == "istio-system" {
			// First mesh-wide policy wins.
			if store.meshWide == nil {
				store.meshWide = pa
			}
		} else {
			// First namespace-scoped policy per namespace wins.
			if _, exists := store.namespacePolicies[pa.Namespace]; !exists {
				store.namespacePolicies[pa.Namespace] = pa
			}
		}
	}
	return store
}

// resolve returns the effective MTLSMode for a service by walking the
// precedence chain: workload → namespace → mesh-wide → default.
func (s *paStore) resolve(svc k8s.Service) MTLSMode {
	// 1. Workload-scoped: find a PA in the same namespace whose selector
	//    is a subset of the service's labels.
	for _, pa := range s.workloadPolicies[svc.Namespace] {
		if labelsMatch(pa.Spec.Selector.MatchLabels, svc.Labels) {
			if mode, ok := extractMode(pa); ok {
				return mode
			}
		}
	}

	// 2. Namespace-scoped.
	if pa, ok := s.namespacePolicies[svc.Namespace]; ok {
		if mode, ok := extractMode(pa); ok {
			return mode
		}
	}

	// 3. Mesh-wide (istio-system, no selector).
	if s.meshWide != nil {
		if mode, ok := extractMode(s.meshWide); ok {
			return mode
		}
	}

	// 4. Default: most Istio installations ship with PERMISSIVE as the
	//    mesh default when no PeerAuthentication applies.
	return ModePermissive
}

// extractMode reads the mTLS mode from a PeerAuthentication. Returns (mode,
// true) when the mode is explicitly set to something actionable (not UNSET).
// UNSET means "inherit from parent level", so the resolver skips it and
// continues up the precedence chain.
func extractMode(pa *istioclientv1beta1.PeerAuthentication) (MTLSMode, bool) {
	if pa.Spec.Mtls == nil {
		return "", false // treated as UNSET — continue up the chain
	}
	switch pa.Spec.Mtls.Mode {
	case istioapi.PeerAuthentication_MutualTLS_STRICT:
		return ModeStrict, true
	case istioapi.PeerAuthentication_MutualTLS_PERMISSIVE:
		return ModePermissive, true
	case istioapi.PeerAuthentication_MutualTLS_DISABLE:
		return ModeDisabled, true
	default: // UNSET
		return "", false
	}
}

// labelsMatch returns true if every key-value pair in selector is present in
// the target label set. An empty selector matches nothing (handled by the
// caller via hasSelector check).
func labelsMatch(selector, target map[string]string) bool {
	for k, v := range selector {
		if target[k] != v {
			return false
		}
	}
	return true
}

// suggestedFix returns a plain-English remediation hint for non-STRICT modes.
func suggestedFix(mode MTLSMode) string {
	switch mode {
	case ModePermissive:
		return "Set PeerAuthentication mode to STRICT to enforce mTLS on all inbound traffic"
	case ModeDisabled:
		return "Remove the DISABLE PeerAuthentication or change its mode to STRICT"
	default:
		return ""
	}
}
