package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version and build metadata",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("meshaudit %s\n", Version)
	},
}
