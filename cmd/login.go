package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lenon/aws-cas-credential-process/cas"
	"github.com/lenon/aws-cas-credential-process/keyring"
	"github.com/lenon/aws-cas-credential-process/sso"
	"github.com/lenon/aws-cas-credential-process/sts"
	"github.com/spf13/cobra"
)

var roleARN, url string

func init() {
	loginCmd.Flags().StringVarP(&url, "url", "u", "", "Identity provider URL")
	loginCmd.Flags().StringVarP(&roleARN, "role-arn", "r", "", "The role ARN to assume")
	loginCmd.MarkFlagRequired("url")
	loginCmd.MarkFlagRequired("role-arn")

	rootCmd.AddCommand(loginCmd)
}

// must follow the format described here
// https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
type output struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

func printCredentials(credentials *sts.Credentials) {
	json, err := json.Marshal(output{
		Version:         1,
		AccessKeyId:     credentials.AccessKeyId,
		SecretAccessKey: credentials.SecretAccessKey,
		SessionToken:    credentials.SessionToken,
		Expiration:      credentials.Expiration,
	})

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(string(json))
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login via web SSO",
	Run: func(cmd *cobra.Command, args []string) {
		login := sso.SSO{
			URL:     url,
			RoleARN: roleARN,
			Keyring: keyring.Open(),
			CAS:     cas.New(url),
		}

		cachedCredentials := login.CachedLogin()

		if cachedCredentials != nil {
			printCredentials(cachedCredentials)
		} else {
			credentials, err := login.Login()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}

			printCredentials(credentials)
		}
	},
}
