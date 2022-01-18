package main

import (
	"os"

	"github.com/lenon/aws-cas-credential-process/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
