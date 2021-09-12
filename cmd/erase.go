package cmd

import (
	"github.com/lenon/aws-cas-credential-process/keyring"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(eraseCmd)
}

var eraseCmd = &cobra.Command{
	Use:   "erase",
	Short: "Erase credentials from the keyring",
	Run: func(cmd *cobra.Command, args []string) {
		keyring := keyring.Open()
		keyring.DeleteAll()
	},
}
