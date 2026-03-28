package k8s

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// forbiddenErr returns a 403 Forbidden error matching k8serrors.IsForbidden.
func forbiddenErr() error {
	return k8serrors.NewForbidden(schema.GroupResource{Resource: "test"}, "", errors.New("forbidden"))
}

// withExitCapture overrides exitFn for the duration of the test and returns
// the exit code that was passed. Restores the original on cleanup.
func withExitCapture(t *testing.T) *int {
	t.Helper()
	code := -1
	orig := exitFn
	exitFn = func(c int) { code = c }
	t.Cleanup(func() { exitFn = orig })
	return &code
}

func TestParseSkipSet(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]bool
	}{
		{"empty string", "", map[string]bool{}},
		{"single value", "kube-system", map[string]bool{"kube-system": true}},
		{"multiple values", "kube-system,istio-system", map[string]bool{"kube-system": true, "istio-system": true}},
		{"whitespace trimming", " kube-system , istio-system ", map[string]bool{"kube-system": true, "istio-system": true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSkipSet(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("ParseSkipSet(%q) len=%d, want %d", tt.input, len(got), len(tt.want))
			}
			for k := range tt.want {
				if !got[k] {
					t.Errorf("expected %q in skip set", k)
				}
			}
		})
	}
}

func TestListNamespaces_AllNamespaces(t *testing.T) {
	client := k8sfake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "staging"}},
	)
	got, err := ListNamespaces(context.Background(), client, "", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 namespaces, got %d: %v", len(got), got)
	}
}

func TestListNamespaces_SkipSet(t *testing.T) {
	client := k8sfake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
	)
	got, err := ListNamespaces(context.Background(), client, "", map[string]bool{"kube-system": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "production" {
		t.Errorf("expected [production], got %v", got)
	}
}

func TestListNamespaces_ScopedNamespace(t *testing.T) {
	client := k8sfake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "staging"}},
	)
	got, err := ListNamespaces(context.Background(), client, "production", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "production" {
		t.Errorf("expected [production], got %v", got)
	}
}

func TestListNamespaces_ScopedNamespace_NotFound(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	_, err := ListNamespaces(context.Background(), client, "nonexistent", map[string]bool{})
	if err == nil {
		t.Error("expected not-found error, got nil")
	}
}

func TestListServices_MultiNamespace(t *testing.T) {
	client := k8sfake.NewSimpleClientset(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{
			Name: "frontend", Namespace: "production",
			Labels: map[string]string{"app": "frontend"},
		}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{
			Name: "backend", Namespace: "staging",
			Labels: map[string]string{"app": "backend"},
		}},
	)
	got, err := ListServices(context.Background(), client, []string{"production", "staging"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 services, got %d", len(got))
	}
	for _, svc := range got {
		if svc.Labels["app"] == "" {
			t.Errorf("expected app label on service %q", svc.Name)
		}
	}
}

func TestListNamespaces_ScopedNamespace_GenericError(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("get", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	_, err := ListNamespaces(context.Background(), client, "production", map[string]bool{})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestListNamespaces_ListError(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("list", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	_, err := ListNamespaces(context.Background(), client, "", map[string]bool{})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestListServices_ListError(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("list", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	_, err := ListServices(context.Background(), client, []string{"production"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestListDeployments_PodLabels(t *testing.T) {
	client := k8sfake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "frontend", Namespace: "production"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "frontend", "version": "v2"},
					},
				},
			},
		},
	)
	deps, err := ListDeployments(context.Background(), client, []string{"production"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 deployment, got %d", len(deps))
	}
	if deps[0].PodLabels["app"] != "frontend" {
		t.Errorf("PodLabels[app] = %q, want %q", deps[0].PodLabels["app"], "frontend")
	}
	if deps[0].PodLabels["version"] != "v2" {
		t.Errorf("PodLabels[version] = %q, want %q", deps[0].PodLabels["version"], "v2")
	}
}

func TestListDeployments_Empty(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	deps, err := ListDeployments(context.Background(), client, []string{"production"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deployments, got %d", len(deps))
	}
}

func TestListDeployments_ListError(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("list", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	_, err := ListDeployments(context.Background(), client, []string{"production"})
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestEnrichServicesWithDeploymentLabels_Match(t *testing.T) {
	services := []Service{
		{Name: "frontend", Namespace: "production", PodSelector: map[string]string{"app": "frontend"}},
	}
	deployments := []Deployment{
		{Name: "frontend", Namespace: "production", PodLabels: map[string]string{"app": "frontend", "version": "v2"}},
	}
	enriched := EnrichServicesWithDeploymentLabels(services, deployments)
	if enriched[0].PodSelector["version"] != "v2" {
		t.Errorf("expected PodSelector enriched with version=v2, got %v", enriched[0].PodSelector)
	}
}

func TestEnrichServicesWithDeploymentLabels_NoMatch(t *testing.T) {
	services := []Service{
		{Name: "frontend", Namespace: "production", PodSelector: map[string]string{"app": "frontend"}},
	}
	deployments := []Deployment{
		{Name: "other", Namespace: "production", PodLabels: map[string]string{"app": "other"}},
	}
	enriched := EnrichServicesWithDeploymentLabels(services, deployments)
	if len(enriched[0].PodSelector) != 1 || enriched[0].PodSelector["app"] != "frontend" {
		t.Errorf("expected unchanged PodSelector, got %v", enriched[0].PodSelector)
	}
}

func TestEnrichServicesWithDeploymentLabels_CrossNamespace(t *testing.T) {
	services := []Service{
		{Name: "frontend", Namespace: "production", PodSelector: map[string]string{"app": "frontend"}},
	}
	deployments := []Deployment{
		{Name: "frontend", Namespace: "staging", PodLabels: map[string]string{"app": "frontend", "env": "staging"}},
	}
	enriched := EnrichServicesWithDeploymentLabels(services, deployments)
	// Should NOT enrich across namespaces.
	if enriched[0].PodSelector["env"] == "staging" {
		t.Errorf("cross-namespace enrichment should not occur")
	}
}

func TestListServices_EmptyNamespaceList(t *testing.T) {
	client := k8sfake.NewSimpleClientset()
	got, err := ListServices(context.Background(), client, []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 services, got %d", len(got))
	}
}

func TestListServices_PodSelectorPopulated(t *testing.T) {
	client := k8sfake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "frontend", Namespace: "production"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "frontend", "version": "v2"},
			},
		},
	)
	svcs, err := ListServices(context.Background(), client, []string{"production"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(svcs) != 1 {
		t.Fatalf("expected 1 service, got %d", len(svcs))
	}
	if svcs[0].PodSelector["app"] != "frontend" {
		t.Errorf("PodSelector[app] = %q, want %q", svcs[0].PodSelector["app"], "frontend")
	}
	if svcs[0].PodSelector["version"] != "v2" {
		t.Errorf("PodSelector[version] = %q, want %q", svcs[0].PodSelector["version"], "v2")
	}
}

// newDynamicFake builds a fake dynamic client pre-populated with VS objects.
func newDynamicFake(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	// Register the VS list type so the fake client can handle List calls.
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1beta1", Kind: "VirtualServiceList"},
		&unstructured.UnstructuredList{},
	)
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1beta1", Kind: "VirtualService"},
		&unstructured.Unstructured{},
	)
	return dynamicfake.NewSimpleDynamicClient(scheme, objects...)
}

func makeVS(name, namespace string, spec map[string]interface{}) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "networking.istio.io",
		Version: "v1beta1",
		Kind:    "VirtualService",
	})
	obj.SetName(name)
	obj.SetNamespace(namespace)
	if err := unstructured.SetNestedMap(obj.Object, spec, "spec"); err != nil {
		panic(err)
	}
	return obj
}

func TestListVirtualServices_ReturnsSpec(t *testing.T) {
	spec := map[string]interface{}{"hosts": []interface{}{"reviews"}}
	dc := newDynamicFake(makeVS("reviews-vs", "production", spec))

	got, err := ListVirtualServices(context.Background(), dc, []string{"production"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 VS, got %d", len(got))
	}
	if got[0].Name != "reviews-vs" {
		t.Errorf("Name = %q, want %q", got[0].Name, "reviews-vs")
	}
	if got[0].Namespace != "production" {
		t.Errorf("Namespace = %q, want %q", got[0].Namespace, "production")
	}
}

func TestListVirtualServices_Empty(t *testing.T) {
	dc := newDynamicFake()
	got, err := ListVirtualServices(context.Background(), dc, []string{"production"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 VS, got %d", len(got))
	}
}

func TestListNamespaces_ForbiddenGet(t *testing.T) {
	code := withExitCapture(t)
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("get", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenErr()
	})
	ListNamespaces(context.Background(), client, "production", map[string]bool{})
	if *code != 2 {
		t.Errorf("expected exit code 2, got %d", *code)
	}
}

func TestListNamespaces_ForbiddenList(t *testing.T) {
	code := withExitCapture(t)
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("list", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenErr()
	})
	ListNamespaces(context.Background(), client, "", map[string]bool{})
	if *code != 2 {
		t.Errorf("expected exit code 2, got %d", *code)
	}
}

func TestListServices_Forbidden(t *testing.T) {
	code := withExitCapture(t)
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("list", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenErr()
	})
	ListServices(context.Background(), client, []string{"production"})
	if *code != 2 {
		t.Errorf("expected exit code 2, got %d", *code)
	}
}

func TestListDeployments_Forbidden(t *testing.T) {
	code := withExitCapture(t)
	client := k8sfake.NewSimpleClientset()
	client.PrependReactor("list", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenErr()
	})
	ListDeployments(context.Background(), client, []string{"production"})
	if *code != 2 {
		t.Errorf("expected exit code 2, got %d", *code)
	}
}

func TestListVirtualServices_MultiNamespace(t *testing.T) {
	dc := newDynamicFake(
		makeVS("vs-a", "production", map[string]interface{}{}),
		makeVS("vs-b", "staging", map[string]interface{}{}),
	)
	got, err := ListVirtualServices(context.Background(), dc, []string{"production", "staging"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 VS, got %d", len(got))
	}
}
