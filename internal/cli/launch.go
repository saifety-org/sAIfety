package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/alexandr-mironov/saifety/internal/launch"
	"github.com/alexandr-mironov/saifety/internal/report"
	"github.com/alexandr-mironov/saifety/internal/scan"
)

func runLaunch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("launch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", DefaultConfigPath(), "config file")
	force := fs.Bool("force", false, "start even when critical findings exist")
	dryRun := fs.Bool("dry-run", false, "scan and print the generated config, do not start claude")
	// Everything after "--" belongs to claude; before it, flags and the
	// directory may come in any order.
	own, rest := args, []string(nil)
	for i, a := range args {
		if a == "--" {
			own, rest = args[:i], args[i+1:]
			break
		}
	}
	if err := fs.Parse(reorderFlags(own, "-config", "--config")); err != nil {
		return ExitUsage
	}
	dir := "."
	if pos := fs.Args(); len(pos) > 0 {
		dir = pos[0]
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return ExitError
	}

	// 1. Scan the repository before anything reads it.
	sum, err := scanPaths(ctx, []string{dir}, cfg, scanOpts{}, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitError
	}
	report.Text(stderr, sum, false)
	if sum.Level >= scan.LevelCritical && !*force {
		fmt.Fprintln(stderr, "\ncritical findings; refusing to start claude (use -force to override)")
		return ExitCritical
	}

	// 2. Generate the session configuration.
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitError
	}
	plan := launch.Plan{Dir: dir, SelfPath: self, ConfigPath: *cfgPath, ClaudeBinary: cfg.ClaudeBinary, ExtraArgs: rest}
	files, err := launch.Prepare(plan)
	if err != nil {
		fmt.Fprintln(stderr, "prepare:", err)
		return ExitError
	}
	if *dryRun {
		fmt.Fprintln(stdout, "settings:", files.Settings)
		fmt.Fprintln(stdout, "mcp:     ", files.MCP)
		fmt.Fprintln(stdout, "command: ", launch.Command(plan, files).String())
		return ExitClean
	}
	defer os.RemoveAll(files.TempDir)

	// 3. Run claude.
	cmd := launch.Command(plan, files)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintln(stderr, "claude:", err)
		return ExitError
	}
	return ExitClean
}

// reorderFlags moves flag arguments in front of positionals so that
// "launch ./dir -dry-run" works like "launch -dry-run ./dir". valueFlags
// names flags that take a separate value argument.
func reorderFlags(args []string, valueFlags ...string) []string {
	takesValue := map[string]bool{}
	for _, f := range valueFlags {
		takesValue[f] = true
	}
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			if takesValue[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}
