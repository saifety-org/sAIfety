package classifier

import (
	"math"
	"math/rand"
	"sort"
	"time"
)

// Sample is a labeled training example. Label 1 = attack on the agent, 0 = benign.
type Sample struct {
	Text  string
	Label float64
}

// TrainOptions tune the logistic-regression SGD.
type TrainOptions struct {
	Epochs int
	LR     float64
	L2     float64
	Seed   int64
}

// DefaultTrain is a reasonable configuration.
var DefaultTrain = TrainOptions{Epochs: 40, LR: 0.5, L2: 1e-5, Seed: 1}

// Train fits a logistic-regression model on the samples with SGD + L2.
func Train(samples []Sample, opts TrainOptions) *Model {
	if opts.Epochs == 0 {
		opts = DefaultTrain
	}
	rng := rand.New(rand.NewSource(opts.Seed))
	// Precompute features once.
	type feature struct {
		key   int
		value float64
	}
	feats := make([][]feature, len(samples))
	for i, s := range samples {
		f := Features(s.Text)
		keys := make([]int, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		for _, k := range keys {
			feats[i] = append(feats[i], feature{k, f[k]})
		}
	}
	w := make([]float64, Dim)
	b := 0.0
	idx := rng.Perm(len(samples))
	for e := 0; e < opts.Epochs; e++ {
		rng.Shuffle(len(idx), func(i, j int) { idx[i], idx[j] = idx[j], idx[i] })
		for _, i := range idx {
			f, y := feats[i], samples[i].Label
			z := b
			for _, item := range f {
				z += w[item.key] * item.value
			}
			p := sigmoid(z)
			g := p - y // gradient of log-loss wrt z
			for _, item := range f {
				j, v := item.key, item.value
				w[j] -= opts.LR * (g*v + opts.L2*w[j])
			}
			b -= opts.LR * g
		}
	}
	return &Model{Dim: Dim, Weights: w, Bias: b, TrainedAt: time.Now().UTC().Format(time.RFC3339)}
}

// Evaluate returns accuracy, precision, recall at threshold 0.5.
func Evaluate(m *Model, samples []Sample) (acc, prec, rec float64) {
	var tp, fp, tn, fn int
	for _, s := range samples {
		p := m.Score(s.Text) >= 0.5
		switch {
		case p && s.Label == 1:
			tp++
		case p && s.Label == 0:
			fp++
		case !p && s.Label == 0:
			tn++
		default:
			fn++
		}
	}
	total := tp + fp + tn + fn
	if total > 0 {
		acc = float64(tp+tn) / float64(total)
	}
	if tp+fp > 0 {
		prec = float64(tp) / float64(tp+fp)
	} else {
		prec = 1
	}
	if tp+fn > 0 {
		rec = float64(tp) / float64(tp+fn)
	} else {
		rec = 1
	}
	return
}

var _ = math.Sqrt
