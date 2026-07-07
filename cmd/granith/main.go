package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const defaultServer = "https://api.granith.dev"

var (
	flagServer string
	flagToken  string
)

func main() {
	root := &cobra.Command{
		Use:   "granith",
		Short: "Granith secrets SDK CLI",
	}

	root.PersistentFlags().StringVar(&flagServer, "server", "", "Granith server URL (or GRANITH_SERVER env; defaults to "+defaultServer+")")
	root.PersistentFlags().StringVar(&flagToken, "token", "", "Granith token (or GRANITH_TOKEN env)")

	root.AddCommand(pingCmd())
	root.AddCommand(runCmd())
	root.AddCommand(exportCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func resolveConfig() (server, rawToken string, err error) {
	server = flagServer
	if server == "" {
		server = os.Getenv("GRANITH_SERVER")
	}
	if server == "" {
		server = defaultServer
	}

	rawToken = flagToken
	if rawToken == "" {
		rawToken = os.Getenv("GRANITH_TOKEN")
	}
	if rawToken == "" {
		return "", "", fmt.Errorf("token required: set --token or GRANITH_TOKEN")
	}

	return server, rawToken, nil
}
