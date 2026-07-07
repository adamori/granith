package main

import (
	"fmt"
	"os"

	"github.com/adamori/granith/pkg/client"
	"github.com/spf13/cobra"
)

func pingCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ping",
		Short: "Check connectivity to the Granith server",
		RunE: func(cmd *cobra.Command, args []string) error {
			server, rawToken, err := resolveConfig()
			if err != nil {
				return err
			}

			c := client.New(server, rawToken)
			if err := c.Ping(); err != nil {
				fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("OK")
			return nil
		},
	}
}
