package k8s

import (
	"fmt"
	"os"

	istioclient "istio.io/client-go/pkg/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Clients holds the two API clients meshaudit needs plus metadata derived
// from the resolved kubeconfig.
type Clients struct {
	Kube        kubernetes.Interface
	Istio       istioclient.Interface
	ClusterName string // name of the active kubeconfig context
}

// New builds both clients from the provided kubeconfig path and context name.
// Either argument may be empty, in which case the usual client-go defaults
// apply ($KUBECONFIG env var, then ~/.kube/config; current context).
//
// On any configuration or connectivity error the function prints a clear
// message and exits with code 2 so the caller never has to handle a nil
// return value.
func New(kubeconfigPath, contextName string) *Clients {
	// 1. Resolve the kubeconfig path ourselves so we can surface a helpful
	//    error before client-go tries (and fails silently).
	if kubeconfigPath == "" {
		if v := os.Getenv("KUBECONFIG"); v != "" {
			kubeconfigPath = v
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				fatal("cannot determine home directory: %v", err)
			}
			kubeconfigPath = home + "/.kube/config"
		}
	}

	// 2. Build the REST config, optionally overriding the active context.
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPath

	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		overrides,
	)

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		fatal(
			"cannot load kubeconfig (%s): %v\n\nTip: set --kubeconfig or ensure ~/.kube/config is valid.",
			kubeconfigPath, err,
		)
	}

	// 3. Resolve the cluster name from the active context for display.
	rawConfig, err := clientConfig.RawConfig()
	clusterName := "unknown"
	if err == nil {
		activeCtx := rawConfig.CurrentContext
		if contextName != "" {
			activeCtx = contextName
		}
		if ctx, ok := rawConfig.Contexts[activeCtx]; ok {
			clusterName = ctx.Cluster
		}
	}

	// 4. Build the standard Kubernetes client.
	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		fatal("cannot create Kubernetes client: %v", err)
	}

	// 5. Build the Istio client.
	istioClient, err := istioclient.NewForConfig(restConfig)
	if err != nil {
		fatal("cannot create Istio client: %v", err)
	}

	return &Clients{
		Kube:        kubeClient,
		Istio:       istioClient,
		ClusterName: clusterName,
	}
}

// fatal prints a formatted error to stderr and exits with code 2.
// Code 2 is reserved for meshaudit errors (vs code 1 for findings).
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "meshaudit error: "+format+"\n", args...)
	os.Exit(2)
}
