package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of aws-cas-credential-process and exit",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("aws-cas-credential-process v0.1")
	},
}
