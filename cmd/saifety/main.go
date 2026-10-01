// Command saifety is an offline analyzer of agent input data: a repository
// scanner, an MCP aggregating proxy, and a Claude Code hook adapter.
package main

import (
	"context"
	"os"

	"github.com/alexandr-mironov/saifety/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
