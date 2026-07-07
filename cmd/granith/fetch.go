package main

import (
	"fmt"
	"os"

	"github.com/adamori/granith/pkg/client"
)

// Status goes to stderr so stdout stays clean for export/run output.
func fetchBundle(c *client.Client, noWait bool) (*client.BundleResponse, error) {
	if noWait {
		return c.FetchBundle()
	}
	return c.FetchBundleAwaitingApproval(func(msg string) {
		fmt.Fprintln(os.Stderr, "granith: "+msg)
	})
}
