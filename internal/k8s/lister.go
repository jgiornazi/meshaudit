package k8s

import (
	"context"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Service is a minimal representation of a Kubernetes Service that the audit
// engine works with. Keeping it small avoids dragging the full corev1.Service
// type through every layer of the codebase.
type Service struct {
	Name      string
	Namespace string
	// Labels are needed so the mTLS scanner can match workload-scoped
	// PeerAuthentication selectors against individual services.
	Labels map[string]string
}

// ListNamespaces returns the set of namespaces to scan. If scopedNamespace is
// non-empty only that namespace is returned (after verifying it exists).
// Namespaces in the skip set are excluded. RBAC errors produce a clear message
// and exit code 2.
func ListNamespaces(ctx context.Context, kube kubernetes.Interface, scopedNamespace string, skipSet map[string]bool) ([]string, error) {
	if scopedNamespace != "" {
		// Validate the requested namespace exists.
		if _, err := kube.CoreV1().Namespaces().Get(ctx, scopedNamespace, metav1.GetOptions{}); err != nil {
			if k8serrors.IsForbidden(err) {
				rbacError("namespaces", scopedNamespace)
			}
			if k8serrors.IsNotFound(err) {
				return nil, fmt.Errorf("namespace %q not found", scopedNamespace)
			}
			return nil, fmt.Errorf("get namespace %q: %w", scopedNamespace, err)
		}
		return []string{scopedNamespace}, nil
	}

	nsList, err := kube.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		if k8serrors.IsForbidden(err) {
			rbacError("namespaces", "")
		}
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	var names []string
	for _, ns := range nsList.Items {
		if skipSet[ns.Name] {
			continue
		}
		names = append(names, ns.Name)
	}
	return names, nil
}

// ListServices returns all Services across the provided namespaces. RBAC
// errors on any individual namespace are surfaced clearly and halt the scan.
func ListServices(ctx context.Context, kube kubernetes.Interface, namespaces []string) ([]Service, error) {
	var services []Service

	for _, ns := range namespaces {
		svcList, err := kube.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			if k8serrors.IsForbidden(err) {
				rbacError("services", ns)
			}
			return nil, fmt.Errorf("list services in %q: %w", ns, err)
		}
		for _, svc := range svcList.Items {
			services = append(services, fromCoreService(svc))
		}
	}
	return services, nil
}

// fromCoreService converts a corev1.Service to the internal Service type.
func fromCoreService(s corev1.Service) Service {
	labels := make(map[string]string, len(s.Labels))
	for k, v := range s.Labels {
		labels[k] = v
	}
	return Service{
		Name:      s.Name,
		Namespace: s.Namespace,
		Labels:    labels,
	}
}

// ParseSkipSet converts a comma-separated namespace string into a lookup map.
func ParseSkipSet(raw string) map[string]bool {
	set := map[string]bool{}
	for _, ns := range strings.Split(raw, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			set[ns] = true
		}
	}
	return set
}

// rbacError prints a helpful RBAC error with the exact kubectl command needed
// to grant the missing permission, then exits with code 2.
func rbacError(resource, namespace string) {
	where := "cluster-wide"
	if namespace != "" {
		where = "in namespace " + namespace
	}
	fmt.Fprintf(os.Stderr, `meshaudit error: permission denied listing %s %s.

Grant the required read access with:

  kubectl apply -f - <<EOF
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: meshaudit-reader
  rules:
  - apiGroups: [""]
    resources: ["namespaces", "services"]
    verbs: ["get", "list"]
  - apiGroups: ["security.istio.io"]
    resources: ["peerauthentications", "authorizationpolicies"]
    verbs: ["get", "list"]
  EOF

`, resource, where)
	os.Exit(2)
}
