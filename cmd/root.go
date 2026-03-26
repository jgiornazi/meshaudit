package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	kubeconfig  string
	kubeContext string
	namespace   string
	output      string
	failOnWarn  bool
)

var rootCmd = &cobra.Command{
	Use:   "meshaudit",
	Short: "Istio mTLS & AuthorizationPolicy security auditor for Kubernetes",
	Long: `meshaudit scans your Istio service mesh for mTLS misconfigurations
and AuthorizationPolicy hygiene issues, producing a prioritized security report.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	rootCmd.PersistentFlags().StringVar(&kubeContext, "context", "", "Kubernetes context to use")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "Limit scan to a single namespace (default: all)")
	rootCmd.PersistentFlags().StringVar(&output, "output", "pretty", "Output format: pretty | json")
	rootCmd.PersistentFlags().BoolVar(&failOnWarn, "fail-on-warn", false, "Exit with code 1 if any WARN or FAIL findings exist")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}
