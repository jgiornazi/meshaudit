package cmd

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/jgiornazi/meshaudit/internal/audit"
	meshk8s "github.com/jgiornazi/meshaudit/internal/k8s"
	"github.com/jgiornazi/meshaudit/internal/report"
)

var skipNamespaces string
var minScore int

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan mTLS posture and AuthorizationPolicies",
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVar(&skipNamespaces, "skip-namespaces", "", "Comma-separated namespaces to exclude")
	scanCmd.Flags().IntVar(&minScore, "min-score", 0, "Fail if posture score is below this threshold (0-100)")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	clients := meshk8s.New(kubeconfig, kubeContext)
	skipSet := meshk8s.ParseSkipSet(skipNamespaces)

	namespaces, err := meshk8s.ListNamespaces(ctx, clients.Kube, namespace, skipSet)
	if err != nil {
		return err
	}

	services, err := meshk8s.ListServices(ctx, clients.Kube, namespaces)
	if err != nil {
		return err
	}

	mtlsFindings, err := audit.ScanMTLS(ctx, clients.Istio, services)
	if err != nil {
		return err
	}

	authzFindings, err := audit.ScanAuthz(ctx, clients.Istio, namespaces)
	if err != nil {
		return err
	}

	w := os.Stdout
	ns := report.NamespaceOrAll(namespace)

	if output == "json" {
		r := report.BuildReport(clients.ClusterName, ns, mtlsFindings, authzFindings)
		if err := report.PrintJSON(w, r); err != nil {
			return err
		}
	} else {
		report.PrintHeader(w, Version, clients.ClusterName, ns)
		report.PrintMTLS(w, mtlsFindings)
		report.PrintAuthz(w, authzFindings)
		report.PrintSummary(w, mtlsFindings, authzFindings)
	}

	// Exit code logic.
	result := audit.Compute(mtlsFindings, authzFindings)
	_, warn, fail := audit.Summary(mtlsFindings, authzFindings)

	if minScore > 0 && result.Score < minScore {
		os.Exit(1)
	}
	if failOnWarn && (warn > 0 || fail > 0) {
		os.Exit(1)
	}

	return nil
}
