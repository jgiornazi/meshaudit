package audit

import (
	"context"
	"fmt"
	"testing"

	istioapi "istio.io/api/security/v1beta1"
	istioapitype "istio.io/api/type/v1beta1"
	istioclientv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	istiofake "istio.io/client-go/pkg/clientset/versioned/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/jgiornazi/meshaudit/internal/k8s"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makePА(namespace, name string, mode istioapi.PeerAuthentication_MutualTLS_Mode, selector map[string]string) *istioclientv1beta1.PeerAuthentication {
	pa := &istioclientv1beta1.PeerAuthentication{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: istioapi.PeerAuthentication{
			Mtls: &istioapi.PeerAuthentication_MutualTLS{
				Mode: mode,
			},
		},
	}
	if len(selector) > 0 {
		pa.Spec.Selector = &istioapitype.WorkloadSelector{
			MatchLabels: selector,
		}
	}
	return pa
}

func makeService(namespace, name string, labels map[string]string) k8s.Service {
	return k8s.Service{Name: name, Namespace: namespace, Labels: labels}
}

// ── precedence tests ──────────────────────────────────────────────────────────

func TestResolve(t *testing.T) {
	appLabels := map[string]string{"app": "payments-svc"}

	tests := []struct {
		name     string
		pas      []*istioclientv1beta1.PeerAuthentication
		service  k8s.Service
		wantMode MTLSMode
	}{
		{
			name:     "no policy defaults to PERMISSIVE",
			pas:      nil,
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModePermissive,
		},
		{
			name: "mesh-wide STRICT applies when no narrower policy exists",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("istio-system", "mesh-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
			},
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModeStrict,
		},
		{
			name: "namespace-scoped overrides mesh-wide",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("istio-system", "mesh-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
				makePА("production", "ns-permissive", istioapi.PeerAuthentication_MutualTLS_PERMISSIVE, nil),
			},
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModePermissive,
		},
		{
			name: "workload-scoped overrides namespace-scoped",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("production", "ns-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
				makePА("production", "wl-disabled", istioapi.PeerAuthentication_MutualTLS_DISABLE, appLabels),
			},
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModeDisabled,
		},
		{
			name: "workload-scoped overrides mesh-wide",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("istio-system", "mesh-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
				makePА("production", "wl-disabled", istioapi.PeerAuthentication_MutualTLS_DISABLE, appLabels),
			},
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModeDisabled,
		},
		{
			name: "workload selector only matches service with matching labels",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("production", "wl-disabled", istioapi.PeerAuthentication_MutualTLS_DISABLE, map[string]string{"app": "other-svc"}),
			},
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModePermissive, // selector doesn't match → fall through to default
		},
		{
			name: "workload selector only matches within the same namespace",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("other-ns", "wl-disabled", istioapi.PeerAuthentication_MutualTLS_DISABLE, appLabels),
			},
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModePermissive,
		},
		{
			name: "UNSET mode is skipped and falls through to next level",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("istio-system", "mesh-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
				// namespace PA with UNSET — should be skipped, mesh-wide should apply
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ns-unset", Namespace: "production"},
					Spec: istioapi.PeerAuthentication{
						Mtls: &istioapi.PeerAuthentication_MutualTLS{
							Mode: istioapi.PeerAuthentication_MutualTLS_UNSET,
						},
					},
				},
			},
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModeStrict,
		},
		{
			name: "nil Mtls field is treated as UNSET and falls through",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("istio-system", "mesh-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ns-nil-mtls", Namespace: "production"},
					Spec:       istioapi.PeerAuthentication{}, // Mtls is nil
				},
			},
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModeStrict,
		},
		{
			name: "workload selector with multiple labels — all must match",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("production", "wl-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, map[string]string{
					"app":     "payments-svc",
					"version": "v2",
				}),
			},
			// Service only has "app" label — partial match should NOT apply
			service:  makeService("production", "payments-svc", map[string]string{"app": "payments-svc"}),
			wantMode: ModePermissive,
		},
		{
			name: "workload selector with multiple labels — all present",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("production", "wl-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, map[string]string{
					"app":     "payments-svc",
					"version": "v2",
				}),
			},
			service: makeService("production", "payments-svc", map[string]string{
				"app":     "payments-svc",
				"version": "v2",
				"team":    "platform", // extra label on service is fine
			}),
			wantMode: ModeStrict,
		},
		{
			name: "explicit DISABLED at workload scope is highest risk",
			pas: []*istioclientv1beta1.PeerAuthentication{
				makePА("istio-system", "mesh-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
				makePА("production", "ns-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
				makePА("production", "wl-disabled", istioapi.PeerAuthentication_MutualTLS_DISABLE, appLabels),
			},
			service:  makeService("production", "payments-svc", appLabels),
			wantMode: ModeDisabled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := buildPAStore(tt.pas)
			got := store.resolve(tt.service)
			if got != tt.wantMode {
				t.Errorf("resolve() = %q, want %q", got, tt.wantMode)
			}
		})
	}
}

// ── suggested fix tests ───────────────────────────────────────────────────────

func TestSuggestedFix(t *testing.T) {
	tests := []struct {
		mode MTLSMode
		want string
	}{
		{ModeStrict, ""},
		{ModePermissive, "Set PeerAuthentication mode to STRICT to enforce mTLS on all inbound traffic"},
		{ModeDisabled, "Remove the DISABLE PeerAuthentication or change its mode to STRICT"},
	}
	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			got := suggestedFix(tt.mode)
			if got != tt.want {
				t.Errorf("suggestedFix(%q) = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

// ── ScanMTLS integration tests (fake client, no cluster needed) ───────────────

func TestScanMTLS(t *testing.T) {
	appLabels := map[string]string{"app": "payments-svc"}

	tests := []struct {
		name      string
		pas       []k8sruntime.Object
		services  []k8s.Service
		wantModes map[string]MTLSMode // service name → expected mode
	}{
		{
			name:     "empty cluster returns PERMISSIVE for all services",
			pas:      nil,
			services: []k8s.Service{makeService("production", "payments-svc", appLabels)},
			wantModes: map[string]MTLSMode{
				"payments-svc": ModePermissive,
			},
		},
		{
			name: "namespace-scoped STRICT applies to all services in namespace",
			pas: []k8sruntime.Object{
				makePА("production", "ns-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
			},
			services: []k8s.Service{
				makeService("production", "payments-svc", appLabels),
				makeService("production", "inventory-svc", map[string]string{"app": "inventory-svc"}),
			},
			wantModes: map[string]MTLSMode{
				"payments-svc":  ModeStrict,
				"inventory-svc": ModeStrict,
			},
		},
		{
			name: "workload-scoped DISABLE overrides namespace STRICT for one service",
			pas: []k8sruntime.Object{
				makePА("production", "ns-strict", istioapi.PeerAuthentication_MutualTLS_STRICT, nil),
				makePА("production", "wl-disabled", istioapi.PeerAuthentication_MutualTLS_DISABLE, appLabels),
			},
			services: []k8s.Service{
				makeService("production", "payments-svc", appLabels),
				makeService("production", "inventory-svc", map[string]string{"app": "inventory-svc"}),
			},
			wantModes: map[string]MTLSMode{
				"payments-svc":  ModeDisabled,  // workload policy applies
				"inventory-svc": ModeStrict,    // only namespace policy applies
			},
		},
		{
			name:      "no services returns empty findings",
			pas:       nil,
			services:  nil,
			wantModes: map[string]MTLSMode{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := istiofake.NewSimpleClientset(tt.pas...)
			findings, err := ScanMTLS(context.Background(), fakeClient, tt.services)

			if err != nil {
				t.Fatalf("ScanMTLS() unexpected error: %v", err)
			}
			if len(findings) != len(tt.wantModes) {
				t.Fatalf("ScanMTLS() returned %d findings, want %d", len(findings), len(tt.wantModes))
			}
			for _, f := range findings {
				want, ok := tt.wantModes[f.Service]
				if !ok {
					t.Errorf("unexpected service in findings: %q", f.Service)
					continue
				}
				if f.Mode != want {
					t.Errorf("service %q: mode = %q, want %q", f.Service, f.Mode, want)
				}
			}
		})
	}
}

// ── ScanMTLS error path ───────────────────────────────────────────────────────

func TestScanMTLS_APIError(t *testing.T) {
	fakeClient := istiofake.NewSimpleClientset()
	// Inject a failure on any list call.
	fakeClient.PrependReactor("list", "peerauthentications", func(action k8stesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, fmt.Errorf("api server unavailable")
	})

	_, err := ScanMTLS(context.Background(), fakeClient, []k8s.Service{
		makeService("production", "payments-svc", map[string]string{"app": "payments-svc"}),
	})
	if err == nil {
		t.Fatal("ScanMTLS() expected error, got nil")
	}
}

// ── labelsMatch tests ─────────────────────────────────────────────────────────

func TestLabelsMatch(t *testing.T) {
	tests := []struct {
		name     string
		selector map[string]string
		target   map[string]string
		want     bool
	}{
		{"empty selector matches anything", map[string]string{}, map[string]string{"app": "foo"}, true},
		{"exact match", map[string]string{"app": "foo"}, map[string]string{"app": "foo"}, true},
		{"subset match", map[string]string{"app": "foo"}, map[string]string{"app": "foo", "env": "prod"}, true},
		{"value mismatch", map[string]string{"app": "foo"}, map[string]string{"app": "bar"}, false},
		{"missing key", map[string]string{"app": "foo"}, map[string]string{"env": "prod"}, false},
		{"empty target", map[string]string{"app": "foo"}, map[string]string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := labelsMatch(tt.selector, tt.target)
			if got != tt.want {
				t.Errorf("labelsMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}
