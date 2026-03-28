package k8s

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

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
