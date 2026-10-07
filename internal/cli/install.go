package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/saifety-org/sAIfety/internal/install"
)

func runInstall(ctx context.Context, args []string, stdout, stderr io.Writer, uninstall bool) int {
	dryRun := false
	var which string
	for _, a := range args {
		switch a {
		case "-dry-run", "--dry-run":
			dryRun = true
		default:
			which = a
		}
	}
	if which == "" {
		fmt.Fprintln(stderr, "usage: saifety", verb(uninstall), "<claude-code|claude-desktop|cursor|windsurf|vscode|all> [-dry-run]")
		return ExitUsage
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitError
	}
	opts := install.Options{Self: self, SaifetyConfig: DefaultConfigPath(), DryRun: dryRun, Out: stdout}

	var targets []install.Target
	if which == "all" {
		targets = install.Targets()
	} else if t, ok := install.Find(which); ok {
		targets = []install.Target{t}
	} else {
		fmt.Fprintln(stderr, "unknown target:", which)
		return ExitUsage
	}

	code := ExitClean
	for _, t := range targets {
		if _, err := os.Stat(t.Path); err != nil {
			if which == "all" {
				continue // skip clients that aren't installed when doing all
			}
			fmt.Fprintf(stderr, "%s: config not found at %s (is the client installed?)\n", t.Name, t.Path)
			code = ExitError
			continue
		}
		if uninstall {
			if err := install.Uninstall(t, opts); err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", t.Name, err)
				code = ExitError
				continue
			}
			fmt.Fprintf(stdout, "%s: restored from backup\n", t.Name)
			continue
		}
		p, err := install.Install(t, opts)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", t.Name, err)
			code = ExitError
			continue
		}
		if dryRun {
			continue
		}
		if p.Installed {
			fmt.Fprintf(stdout, "%s: already routed through saifety\n", t.Name)
		} else {
			fmt.Fprintf(stdout, "%s: moved %d server(s) under saifety, backup at %s\n", t.Name, len(p.Moved), p.Backup)
		}
	}
	if !uninstall && !dryRun && code == ExitClean {
		fmt.Fprintln(stdout, "Restart the client to apply. Undo with: saifety uninstall", which)
	}
	return code
}

func verb(uninstall bool) string {
	if uninstall {
		return "uninstall"
	}
	return "install"
}
