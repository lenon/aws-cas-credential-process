package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "aws-cas-helper",
	Short: "A small tool which adds support for web SSO authentication on AWS CLI",
}

func Execute() error {
	return rootCmd.Execute()
}
