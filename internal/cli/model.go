package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/alexandr-mironov/saifety/internal/model"
)

func runModel(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	sub := "status"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	b, err := model.DefaultBundle()
	if err != nil {
		fmt.Fprintln(stderr, "model:", err)
		return ExitError
	}
	pii, piiErr := model.PIIBundle()
	switch sub {
	case "pull":
		force := len(args) > 0 && (args[0] == "-force" || args[0] == "--force")
		fmt.Fprintf(stdout, "provisioning models into %s\n", model.CacheDir())
		if err := b.Pull(stdout, force); err != nil {
			fmt.Fprintln(stderr, "pull (injection):", err)
			return ExitError
		}
		if piiErr == nil {
			if err := pii.Pull(stdout, force); err != nil {
				fmt.Fprintln(stderr, "pull (pii):", err)
				return ExitError
			}
		}
		fmt.Fprintln(stdout, "done. Build with -tags onnx to use them.")
		return ExitClean
	case "status":
		fmt.Fprintf(stdout, "cache: %s\n", model.CacheDir())
		arts := []model.Artifact{b.Runtime, b.Tokenizer, b.Model}
		if piiErr == nil {
			arts = append(arts, pii.Tokenizer, pii.Config, pii.Model)
		}
		for _, a := range arts {
			state := "missing"
			if fi, err := os.Stat(model.Path(a)); err == nil {
				state = fmt.Sprintf("%d bytes", fi.Size())
			}
			fmt.Fprintf(stdout, "  %-20s %s\n", a.Name, state)
		}
		fmt.Fprintf(stdout, "injection ready: %v\n", b.Present())
		if piiErr == nil {
			fmt.Fprintf(stdout, "pii ready: %v\n", pii.Present())
		}
		return ExitClean
	case "path":
		fmt.Fprintln(stdout, model.Path(b.Model))
		fmt.Fprintln(stdout, model.Path(b.Tokenizer))
		fmt.Fprintln(stdout, model.RuntimeLibPath())
		return ExitClean
	default:
		fmt.Fprintln(stderr, "usage: saifety model <pull|status|path>")
		return ExitUsage
	}
}
