package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jgiornazi/meshaudit/internal/audit"
	meshk8s "github.com/jgiornazi/meshaudit/internal/k8s"
	"github.com/jgiornazi/meshaudit/internal/report"
)

var errFindings = errors.New("findings exceed threshold")

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

func checkThresholds(score, minScore int, failOnWarn bool, warn, fail int) error {
	if minScore > 0 && score < minScore {
		return errFindings
	}
	if failOnWarn && (warn > 0 || fail > 0) {
		return errFindings
	}
	return nil
}

func runScan(cmd *cobra.Command, args []string) error {
	switch output {
	case "pretty", "json":
		// valid
	default:
		return fmt.Errorf("unknown output format %q: must be \"pretty\" or \"json\"", output)
	}

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

	deployments, err := meshk8s.ListDeployments(ctx, clients.Kube, namespaces)
	if err != nil {
		return err
	}
	services = meshk8s.EnrichServicesWithDeploymentLabels(services, deployments)

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

	return checkThresholds(result.Score, minScore, failOnWarn, warn, fail)
}
