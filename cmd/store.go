package cmd

import (
	"fmt"
	"os"

	"github.com/lenon/aws-cas-credential-process/keyring"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

func init() {
	rootCmd.AddCommand(storeCmd)
}

func execStore() error {
	var username string

	fmt.Print("AWS username: ")
	fmt.Scanln(&username)

	credentials := keyring.Open()

	if err := credentials.SetUsername(username); err != nil {
		return err
	}

	fmt.Print("AWS password: ")
	readPassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	fmt.Println()

	password := string(readPassword)

	if err := credentials.SetPassword(password); err != nil {
		return err
	}
	return nil
}

var storeCmd = &cobra.Command{
	Use:   "store",
	Short: "Store credentials in the keyring",
	Run: func(cmd *cobra.Command, args []string) {
		if err := execStore(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	},
}
