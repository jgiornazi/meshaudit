package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jgiornazi/meshaudit/internal/drift"
	meshk8s "github.com/jgiornazi/meshaudit/internal/k8s"
	"github.com/jgiornazi/meshaudit/internal/report"
)

var gitPath string

var driftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Detect VirtualService drift vs local YAML manifests",
	Long: `drift compares live Istio VirtualService resources in the cluster against
a local directory of YAML manifests (your desired state from Git).

It reports IN_SYNC, DRIFT_DETECTED, LIVE_ONLY, or MANIFEST_ONLY for each
VirtualService and exits non-zero when drift is found (with --fail-on-warn).`,
	RunE: runDrift,
}

func init() {
	driftCmd.Flags().StringVar(&gitPath, "git-path", "", "Path to local directory of Istio YAML manifests (required)")
}

func runDrift(cmd *cobra.Command, args []string) error {
	if gitPath == "" {
		return fmt.Errorf("--git-path is required")
	}
	if _, err := os.Stat(gitPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("--git-path %q does not exist", gitPath)
		}
		return fmt.Errorf("--git-path: %w", err)
	}

	switch output {
	case "pretty", "json":
		// valid
	default:
		return fmt.Errorf("unknown output format %q: must be \"pretty\" or \"json\"", output)
	}

	ctx := context.Background()
	clients := meshk8s.New(kubeconfig, kubeContext)
	ns := report.NamespaceOrAll(namespace)

	// Determine namespaces to scan.
	namespaces, err := meshk8s.ListNamespaces(ctx, clients.Kube, namespace, map[string]bool{})
	if err != nil {
		return err
	}

	// Fetch live VirtualServices from cluster.
	liveVSes, err := meshk8s.ListVirtualServices(ctx, clients.Dynamic, namespaces)
	if err != nil {
		return err
	}

	// Load desired VirtualServices from local YAML manifests.
	desiredVSes, err := drift.LoadManifests(gitPath, namespace)
	if err != nil {
		return err
	}

	// Compare.
	results := drift.Compare(liveVSes, desiredVSes)

	w := os.Stdout
	scannedAt := time.Now()

	if output == "json" {
		if err := report.PrintDriftJSON(w, clients.ClusterName, scannedAt, ns, results); err != nil {
			return err
		}
	} else {
		report.PrintHeader(w, Version, clients.ClusterName, ns)
		report.PrintDrift(w, results)
	}

	// Exit code logic: exit 1 if --fail-on-warn and any drift detected.
	if failOnWarn {
		for _, r := range results {
			if r.Status != drift.StatusInSync {
				return errFindings
			}
		}
	}

	return nil
}
