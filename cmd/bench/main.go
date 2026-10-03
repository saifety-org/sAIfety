//go:build onnx

// Command bench scores frozen validation/test inputs with both models.
// No rule detectors, gating, training or threshold selection happens here.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"time"

	"github.com/alexandr-mironov/saifety/internal/classifier"
	"github.com/alexandr-mironov/saifety/internal/evaluation"
	"github.com/alexandr-mironov/saifety/internal/model"
	"github.com/alexandr-mironov/saifety/internal/scan/classify"
)

type sample = evaluation.Sample
type result = evaluation.Prediction
type checked interface {
	ScoreChecked(string) (float64, error)
	TokenCount(string) (int, error)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func hash(path string) string {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	must(err)
	return hex.EncodeToString(h.Sum(nil))
}
func main() {
	data := flag.String("data", "artifacts/comparison/evaluation.jsonl", "frozen evaluation JSONL")
	weights := flag.String("weights", "artifacts/comparison/weights.json", "explicit candidate weights")
	out := flag.String("out", "artifacts/comparison/predictions.jsonl", "per-sample output")
	flag.Parse()
	b, err := os.ReadFile(*weights)
	must(err)
	var trainingMeta map[string]any
	metadata, err := os.ReadFile(*weights + ".meta.json")
	must(err)
	must(json.Unmarshal(metadata, &trainingMeta))
	if trainingMeta["weights_sha256"] != hash(*weights) {
		panic("training metadata does not match weights")
	}
	loadStart := time.Now()
	ours, err := classifier.Load(b)
	must(err)
	if ours.Dim != classifier.Dim || len(ours.Weights) != classifier.Dim {
		panic("invalid classifier dimensions")
	}
	oursLoad := time.Since(loadStart).Seconds()
	shipped, err := classifier.Default()
	must(err)
	bundle, err := model.DefaultBundle()
	must(err)
	loadStart = time.Now()
	c, err := classify.NewONNX(classify.ONNXConfig{LibraryPath: model.RuntimeLibPath(), ModelPath: model.Path(bundle.Model), TokenizerPath: model.Path(bundle.Tokenizer), InjectionIndex: bundle.InjectionIndex})
	must(err)
	debertaLoad := time.Since(loadStart).Seconds()
	dc, ok := c.(checked)
	if !ok {
		panic("ONNX backend must expose checked inference")
	}
	f, err := os.Open(*data)
	must(err)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	var rows []sample
	seen := map[string]bool{}
	for scanner.Scan() {
		var row sample
		must(json.Unmarshal(scanner.Bytes(), &row))
		if row.ID == "" || seen[row.ID] || row.Text == "" || (row.Label != 0 && row.Label != 1) || (row.Split != "validation" && row.Split != "test") {
			panic("invalid or duplicate evaluation row")
		}
		seen[row.ID] = true
		rows = append(rows, row)
	}
	must(scanner.Err())
	if len(rows) == 0 {
		panic("empty evaluation corpus")
	}
	// Warm both models equally; do not include initialization in inference time.
	for i := 0; i < 3; i++ {
		ours.Score("The build completed successfully.")
		shipped.Score("The build completed successfully.")
		_, err = dc.ScoreChecked("The build completed successfully.")
		must(err)
	}
	output, err := os.Create(*out)
	must(err)
	defer output.Close()
	enc := json.NewEncoder(output)
	excluded := 0
	for i, row := range rows {
		n, err := dc.TokenCount(row.Text)
		must(err)
		r := result{Sample: row, Tokens: n}
		if n > 512 {
			r.Excluded = "over_shared_512_token_window"
			excluded++
		} else {
			scoreOurs := func() {
				start := time.Now()
				r.Ours = ours.Score(row.Text)
				r.OursMS = float64(time.Since(start)) / float64(time.Millisecond)
			}
			scoreDeberta := func() {
				start := time.Now()
				r.Deberta, err = dc.ScoreChecked(row.Text)
				must(err)
				r.DebertaMS = float64(time.Since(start)) / float64(time.Millisecond)
			}
			scoreShipped := func() {
				start := time.Now()
				r.Shipped = shipped.Score(row.Text)
				r.ShippedMS = float64(time.Since(start)) / float64(time.Millisecond)
			}
			// Alternate order; run sequentially to avoid contention between models.
			if i%2 == 0 {
				scoreOurs()
				scoreShipped()
				scoreDeberta()
			} else {
				scoreDeberta()
				scoreShipped()
				scoreOurs()
			}
			if math.IsNaN(r.Ours) || math.IsNaN(r.Shipped) || math.IsNaN(r.Deberta) || r.Ours < 0 || r.Ours > 1 || r.Shipped < 0 || r.Shipped > 1 || r.Deberta < 0 || r.Deberta > 1 {
				panic("invalid score")
			}
		}
		must(enc.Encode(r))
		if (i+1)%50 == 0 {
			fmt.Fprintf(os.Stderr, "scored %d/%d (excluded long=%d)\n", i+1, len(rows), excluded)
		}
	}
	must(output.Sync())
	meta := map[string]any{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "logical_cpus": runtime.NumCPU(), "data_sha256": hash(*data), "weights_sha256": hash(*weights), "shipped_weights_sha256": hash("internal/classifier/weights.json"), "deberta_sha256": hash(model.Path(bundle.Model)), "tokenizer_sha256": hash(model.Path(bundle.Tokenizer)), "runtime_sha256": hash(model.RuntimeLibPath()), "ours_load_seconds": oursLoad, "deberta_load_seconds": debertaLoad, "rows": len(rows), "excluded_long": excluded, "inference_errors": 0, "batch_size": 1, "warmup": 3, "max_shared_tokens": 512, "preprocessing": "identical raw text; model-native feature/tokenizer transforms; no rules or gating"}
	meta["training"] = trainingMeta
	b, err = json.MarshalIndent(meta, "", "  ")
	must(err)
	must(os.WriteFile(*out+".meta.json", b, 0644))
	fmt.Fprintf(os.Stderr, "finished: %d scored, %d excluded; %s\n", len(rows)-excluded, excluded, *out)
}
