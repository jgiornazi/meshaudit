package k8s

import (
	"context"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// vsGVR is the GroupVersionResource for Istio VirtualServices.
var vsGVR = schema.GroupVersionResource{
	Group:    "networking.istio.io",
	Version:  "v1beta1",
	Resource: "virtualservices",
}

// VirtualService is a minimal representation of an Istio VirtualService used
// by the drift engine to compare live cluster state against desired YAML state.
type VirtualService struct {
	Name      string
	Namespace string
	// Spec holds the raw VirtualService spec as a generic map for field-level
	// diffing. Using map[string]interface{} avoids tight coupling to a specific
	// Istio API version and handles any spec fields uniformly.
	Spec map[string]interface{}
}

// ListVirtualServices returns all VirtualServices across the provided namespaces
// using the dynamic client, which natively returns map[string]interface{} for
// field-level diffing without any protobuf serialization complexity.
// RBAC errors are surfaced with a clear message.
func ListVirtualServices(ctx context.Context, dc dynamic.Interface, namespaces []string) ([]VirtualService, error) {
	var vsList []VirtualService
	for _, ns := range namespaces {
		list, err := dc.Resource(vsGVR).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			if k8serrors.IsForbidden(err) {
				rbacError("virtualservices", ns)
			}
			return nil, fmt.Errorf("list VirtualServices in %q: %w", ns, err)
		}
		for _, item := range list.Items {
			spec, _ := item.Object["spec"].(map[string]interface{})
			if spec == nil {
				spec = map[string]interface{}{}
			}
			vsList = append(vsList, VirtualService{
				Name:      item.GetName(),
				Namespace: item.GetNamespace(),
				Spec:      spec,
			})
		}
	}
	return vsList, nil
}

// Deployment holds the pod template labels from a Kubernetes Deployment,
// which are the labels that PeerAuthentication workload selectors target.
type Deployment struct {
	Name      string
	Namespace string
	// PodLabels are spec.template.metadata.labels — the labels applied to
	// pods created by this Deployment. PA workload selectors match these.
	PodLabels map[string]string
}

// Service is a minimal representation of a Kubernetes Service that the audit
// engine works with. Keeping it small avoids dragging the full corev1.Service
// type through every layer of the codebase.
type Service struct {
	Name      string
	Namespace string
	// Labels are the Service's own metadata labels.
	Labels map[string]string
	// PodSelector is the Service's spec.selector — the pod labels used to
	// route traffic to backing pods. PeerAuthentication workload selectors
	// target pod labels, so this is the correct field to match against.
	PodSelector map[string]string
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
	podSelector := make(map[string]string, len(s.Spec.Selector))
	for k, v := range s.Spec.Selector {
		podSelector[k] = v
	}
	return Service{
		Name:        s.Name,
		Namespace:   s.Namespace,
		Labels:      labels,
		PodSelector: podSelector,
	}
}

// ListDeployments returns the pod template labels for all Deployments across
// the provided namespaces. These labels are what PeerAuthentication workload
// selectors target (spec.template.metadata.labels), which can differ from a
// Service's own metadata labels.
func ListDeployments(ctx context.Context, kube kubernetes.Interface, namespaces []string) ([]Deployment, error) {
	var deployments []Deployment
	for _, ns := range namespaces {
		depList, err := kube.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			if k8serrors.IsForbidden(err) {
				rbacError("deployments", ns)
			}
			return nil, fmt.Errorf("list deployments in %q: %w", ns, err)
		}
		for _, dep := range depList.Items {
			podLabels := make(map[string]string, len(dep.Spec.Template.Labels))
			for k, v := range dep.Spec.Template.Labels {
				podLabels[k] = v
			}
			deployments = append(deployments, Deployment{
				Name:      dep.Name,
				Namespace: dep.Namespace,
				PodLabels: podLabels,
			})
		}
	}
	return deployments, nil
}

// EnrichServicesWithDeploymentLabels updates each Service's PodSelector with
// the full pod template labels from its backing Deployment when a match is
// found. A Deployment matches a Service when it is in the same namespace and
// its pod template labels contain all entries of the Service's pod selector.
// Services with no matching Deployment are returned unchanged.
func EnrichServicesWithDeploymentLabels(services []Service, deployments []Deployment) []Service {
	enriched := make([]Service, len(services))
	copy(enriched, services)

	for i, svc := range enriched {
		if len(svc.PodSelector) == 0 {
			continue
		}
		for _, dep := range deployments {
			if dep.Namespace != svc.Namespace {
				continue
			}
			if labelsContain(dep.PodLabels, svc.PodSelector) {
				merged := make(map[string]string, len(dep.PodLabels))
				for k, v := range dep.PodLabels {
					merged[k] = v
				}
				enriched[i].PodSelector = merged
				break
			}
		}
	}
	return enriched
}

// labelsContain returns true when target contains every key-value pair in selector.
func labelsContain(target, selector map[string]string) bool {
	for k, v := range selector {
		if target[k] != v {
			return false
		}
	}
	return true
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

// exitFn is the function called by rbacError to terminate the process.
// It is a variable so tests can override it to avoid actually calling os.Exit.
var exitFn = func(code int) { os.Exit(code) }

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
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list"]
  - apiGroups: ["security.istio.io"]
    resources: ["peerauthentications", "authorizationpolicies"]
    verbs: ["get", "list"]
  - apiGroups: ["networking.istio.io"]
    resources: ["virtualservices"]
    verbs: ["get", "list"]
  EOF

`, resource, where)
	exitFn(2)
}
