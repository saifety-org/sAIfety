// Command comparison prepares frozen datasets and reports paired model scores.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func hashBytes(b []byte) string   { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func hashFile(path string) string { b, err := os.ReadFile(path); must(err); return hashBytes(b) }
func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile(path, append(b, '\n'), 0644))
}
func readJSON(path string, v any) { b, err := os.ReadFile(path); must(err); must(json.Unmarshal(b, v)) }
func readLines[T any](path string) []T {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4<<20)
	var rows []T
	for sc.Scan() {
		var row T
		must(json.Unmarshal(sc.Bytes(), &row))
		rows = append(rows, row)
	}
	must(sc.Err())
	if len(rows) == 0 {
		panic("empty corpus: " + path)
	}
	return rows
}
func writeLines[T any](path string, rows []T) string {
	f, err := os.Create(path)
	must(err)
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, row := range rows {
		must(enc.Encode(row))
	}
	must(f.Close())
	return hashFile(path)
}
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: comparison prepare|report [-dir artifacts/comparison]")
		os.Exit(64)
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := flags.String("dir", "artifacts/comparison", "artifact directory")
	flags.Parse(os.Args[2:])
	must(os.MkdirAll(filepath.Join(*dir, "raw"), 0755))
	switch os.Args[1] {
	case "prepare":
		prepare(*dir)
	case "report":
		report(*dir)
	default:
		panic("unknown command")
	}
}
