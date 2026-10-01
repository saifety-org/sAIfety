// Command gen trains the attack-on-agent classifier on synthetic + real data
// and writes the embedded weights. Real data: public prompt-injection datasets
// (Apache-2.0) in data/external.jsonl and legitimate commands harvested from
// local repo docs in data/local_benign.jsonl. Metrics are reported on a
// held-out split of the REAL data, so they reflect generalization, not
// memorization of templates.
//
//go:generate go run ./gen -out ../weights.json -data data
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/alexandr-mironov/saifety/internal/classifier"
)

func main() {
	out := flag.String("out", "weights.json", "output weights file")
	dataDir := flag.String("data", "data", "directory with external.jsonl / local_benign.jsonl")
	seed := flag.Int64("seed", 1, "seed")
	flag.Parse()

	synth := classifier.Generate(*seed)
	external := classifier.LoadCorpus(filepath.Join(*dataDir, "external.jsonl"))
	local := classifier.LoadCorpus(filepath.Join(*dataDir, "local_benign.jsonl"))

	// Hold out 15% of the REAL external data (stratified) for honest eval.
	rng := rand.New(rand.NewSource(*seed))
	rng.Shuffle(len(external), func(i, j int) { external[i], external[j] = external[j], external[i] })
	cut := len(external) * 15 / 100
	heldout := external[:cut]
	extTrain := external[cut:]

	train := append([]classifier.Sample{}, synth...)
	train = append(train, extTrain...)
	train = append(train, local...)

	m := classifier.Train(train, classifier.DefaultTrain)
	acc, prec, rec := classifier.Evaluate(m, heldout)
	m.Accuracy, m.Precision, m.Recall = acc, prec, rec

	b, err := m.JSON()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "train: synth=%d external=%d local=%d | held-out(real)=%d\n", len(synth), len(external), len(local), len(heldout))
	fmt.Fprintf(os.Stderr, "REAL held-out: acc=%.3f prec=%.3f rec=%.3f | wrote %s (%d bytes)\n", acc, prec, rec, *out, len(b))
}
