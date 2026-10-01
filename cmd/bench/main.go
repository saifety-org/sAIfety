//go:build onnx

// Command bench compares our embedded trained classifier against the DeBERTa
// ONNX model on the same held-out data, so the value of the ~738MB model can
// be judged after the classifier work. Build with -tags onnx; needs the model
// in the cache (saifety model pull).
package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/alexandr-mironov/saifety/internal/classifier"
	"github.com/alexandr-mironov/saifety/internal/model"
	"github.com/alexandr-mironov/saifety/internal/scan/classify"
)

type scorer struct {
	name string
	fn   func(string) float64
}

func metrics(name string, s []classifier.Sample, fn func(string) float64) {
	var tp, fp, tn, fn_ int
	start := time.Now()
	for _, x := range s {
		p := fn(x.Text) >= 0.5
		switch {
		case p && x.Label == 1:
			tp++
		case p && x.Label == 0:
			fp++
		case !p && x.Label == 0:
			tn++
		default:
			fn_++
		}
	}
	dur := time.Since(start)
	acc := float64(tp+tn) / float64(len(s))
	prec := 1.0
	if tp+fp > 0 {
		prec = float64(tp) / float64(tp+fp)
	}
	rec := 1.0
	if tp+fn_ > 0 {
		rec = float64(tp) / float64(tp+fn_)
	}
	fmt.Printf("%-12s acc=%.3f prec=%.3f rec=%.3f | %d samples in %v (%.1f/s)\n",
		name, acc, prec, rec, len(s), dur.Round(time.Millisecond), float64(len(s))/dur.Seconds())
}

func main() {
	// Use the SAME held-out split gen uses (seed 1, first 15%): rows our
	// model never trained on. DeBERTa never saw any external data, so this is
	// fair to both. Caveat: the held-out is from the same public sources our
	// model trained on, so our model still has a same-distribution edge; a
	// neutral benchmark (e.g. Lakera PINT) would be more balanced but its
	// data is private.
	all := classifier.LoadCorpus("internal/classifier/data/external.jsonl")
	rng := rand.New(rand.NewSource(1))
	rng.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	data := all[:len(all)*15/100]

	our, err := classifier.Default()
	if err != nil {
		panic(err)
	}
	metrics("trained(ours)", data, our.Score)

	cache := os.Getenv("SAIFETY_CACHE")
	if cache == "" {
		home, _ := os.UserHomeDir()
		cache = filepath.Join(home, ".cache", "saifety")
	}
	b, _ := model.DefaultBundle()
	deberta, err := classify.NewONNX(classify.ONNXConfig{
		LibraryPath:    model.RuntimeLibPath(),
		ModelPath:      model.Path(b.Model),
		TokenizerPath:  model.Path(b.Tokenizer),
		InjectionIndex: b.InjectionIndex,
	})
	if err != nil {
		fmt.Println("DeBERTa unavailable:", err)
		return
	}
	metrics("deberta-738MB", data, deberta.Score)
}
