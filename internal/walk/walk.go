// Package walk enumerates the files of a repository for scanning. It skips
// VCS and dependency directories, binaries and oversized files, and labels
// instruction and agent-config files so the scanner can weigh them.
package walk

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexandr-mironov/saifety/internal/scan"
	"github.com/alexandr-mironov/saifety/internal/scan/extract"
	"github.com/alexandr-mironov/saifety/internal/scan/rules"
)

// Options tune the walk.
type Options struct {
	MaxFileSize int64
	SkipDirs    []string
}

var DefaultOptions = Options{
	MaxFileSize: 2 << 20,
	SkipDirs:    []string{".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", "target", ".idea", ".vscode"},
}

// Entry is one file to scan.
type Entry struct {
	Path string
	Kind scan.Kind
	Size int64
}

// Files lists scannable files under root. Instruction and agent-config
// files come first so a report shows them at the top.
func Files(root string, opts Options) ([]Entry, error) {
	if opts.MaxFileSize == 0 {
		opts.MaxFileSize = DefaultOptions.MaxFileSize
	}
	if opts.SkipDirs == nil {
		opts.SkipDirs = DefaultOptions.SkipDirs
	}
	skip := map[string]bool{}
	for _, d := range opts.SkipDirs {
		skip[d] = true
	}
	var prio, rest []Entry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		if d.IsDir() {
			if path != root && skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		// Only regular files: skip symlinks, sockets, FIFOs, devices.
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > opts.MaxFileSize {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		e := Entry{Path: path, Kind: Classify(rel), Size: info.Size()}
		switch e.Kind {
		case scan.KindFile:
			if bin, _ := isBinary(path); bin {
				return nil
			}
			rest = append(rest, e)
		case scan.KindImage:
			rest = append(rest, e)
		default:
			prio = append(prio, e)
		}
		return nil
	})
	return append(prio, rest...), err
}

// Classify labels a repo-relative path by how agents treat it.
func Classify(rel string) scan.Kind {
	rel = filepath.ToSlash(rel)
	base := filepath.Base(rel)
	if extract.IsImage(strings.ToLower(filepath.Ext(base))) {
		return scan.KindImage
	}
	for _, p := range rules.AgentConfigFiles {
		if rel == p || strings.HasSuffix(rel, "/"+p) {
			return scan.KindAgentConfig
		}
	}
	for _, p := range rules.InstructionFiles {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(rel, p) || strings.Contains(rel, "/"+p) {
				return scan.KindInstructions
			}
			continue
		}
		if base == p || rel == p || strings.HasSuffix(rel, "/"+p) {
			return scan.KindInstructions
		}
	}
	return scan.KindFile
}

// isBinary sniffs the first 8 KiB for NUL bytes.
func isBinary(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	return bytes.IndexByte(buf[:n], 0) >= 0, nil
}
