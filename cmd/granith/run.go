package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/adamori/granith/pkg/bundle"
	"github.com/adamori/granith/pkg/client"
	"github.com/adamori/granith/pkg/crypto"
	"github.com/adamori/granith/pkg/token"
	"github.com/spf13/cobra"
)

func runCmd() *cobra.Command {
	var noWait bool

	cmd := &cobra.Command{
		Use:   "run [--] command [args...]",
		Short: "Fetch secrets and exec a command with them as env vars",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, rawToken, err := resolveConfig()
			if err != nil {
				return err
			}

			tok, err := token.Parse(rawToken)
			if err != nil {
				return fmt.Errorf("parse token: %w", err)
			}
			defer tok.Zero()

			c := client.New(server, rawToken)
			resp, err := fetchBundle(c, noWait)
			if err != nil {
				return fmt.Errorf("fetch bundle: %w", err)
			}

			b, err := bundle.Decrypt(resp.Body, tok.TokenKey)
			if err != nil {
				return fmt.Errorf("decrypt bundle: %w", err)
			}

			crypto.Zero(tok.TokenKey)

			env := os.Environ()
			for _, s := range b.Secrets {
				env = append(env, s.Name+"="+s.Value)
			}

			binary, err := exec.LookPath(args[0])
			if err != nil {
				return fmt.Errorf("find command %q: %w", args[0], err)
			}

			return syscall.Exec(binary, args, env)
		},
	}

	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Fail immediately instead of waiting for owner approval")
	return cmd
}
