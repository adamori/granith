package main

import (
	"fmt"
	"strings"

	"github.com/adamori/granith/pkg/bundle"
	"github.com/adamori/granith/pkg/client"
	"github.com/adamori/granith/pkg/crypto"
	"github.com/adamori/granith/pkg/token"
	"github.com/spf13/cobra"
)

func exportCmd() *cobra.Command {
	var format string
	var noWait bool

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Fetch and print secrets (dotenv, json, or shell format)",
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

			switch format {
			case "dotenv":
				for _, s := range b.Secrets {
					fmt.Printf("%s=%s\n", s.Name, s.Value)
				}
			case "shell":
				for _, s := range b.Secrets {
					fmt.Printf("export %s=%s\n", s.Name, shellQuote(s.Value))
				}
			case "json":
				fmt.Print("{")
				for i, s := range b.Secrets {
					if i > 0 {
						fmt.Print(",")
					}
					fmt.Printf("%q:%q", s.Name, s.Value)
				}
				fmt.Println("}")
			default:
				return fmt.Errorf("unknown format %q (use dotenv, shell, or json)", format)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "dotenv", "Output format: dotenv, shell, json")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Fail immediately instead of waiting for owner approval")
	return cmd
}

func shellQuote(s string) string {
	if !strings.ContainsAny(s, " \t\n'\"\\$`!#&|;(){}") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
