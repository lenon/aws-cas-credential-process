package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// replaced via ldflags in the release script
var gitTag = "v0.0.0"
var gitCommit = "none"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of aws-cas-credential-process and exit",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(fmt.Sprintf("aws-cas-credential-process %s %s", gitTag, gitCommit))
	},
}
