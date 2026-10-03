// Package evaluation implements model-independent benchmark accounting.
package evaluation

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
)

type Sample struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Label    int    `json:"label"`
	Family   string `json:"family"`
	Category string `json:"category"`
	Language string `json:"language"`
	Split    string `json:"split"`
	Group    string `json:"group"`
}

type Prediction struct {
	Sample
	Tokens    int     `json:"tokens"`
	Excluded  string  `json:"excluded,omitempty"`
	Ours      float64 `json:"ours"`
	Shipped   float64 `json:"shipped"`
	Deberta   float64 `json:"deberta"`
	OursMS    float64 `json:"ours_ms"`
	ShippedMS float64 `json:"shipped_ms"`
	DebertaMS float64 `json:"deberta_ms"`
}

func (r Prediction) Score(model string) float64 {
	switch model {
	case "ours":
		return r.Ours
	case "shipped":
		return r.Shipped
	default:
		return r.Deberta
	}
}
func (r Prediction) Latency(model string) float64 {
	switch model {
	case "ours":
		return r.OursMS
	case "shipped":
		return r.ShippedMS
	default:
		return r.DebertaMS
	}
}

type Metrics struct {
	N                int       `json:"n"`
	TP               int       `json:"tp"`
	FN               int       `json:"fn"`
	FP               int       `json:"fp"`
	TN               int       `json:"tn"`
	Threshold        float64   `json:"threshold"`
	Precision        *float64  `json:"precision"`
	Recall           *float64  `json:"recall"`
	FPR              *float64  `json:"fpr"`
	F1               *float64  `json:"f1"`
	Accuracy         *float64  `json:"accuracy"`
	BalancedAccuracy *float64  `json:"balanced_accuracy"`
	AUROC            *float64  `json:"auroc"`
	AveragePrecision *float64  `json:"average_precision"`
	RecallCI95       []float64 `json:"recall_ci95"`
	FPRCI95          []float64 `json:"fpr_ci95"`
	MedianMS         float64   `json:"median_ms"`
	P95MS            float64   `json:"p95_ms"`
	SamplesPerSecond float64   `json:"samples_per_second"`
}

func ptr(v float64) *float64 { return &v }
func ratio(a, b int) *float64 {
	if b == 0 {
		return nil
	}
	return ptr(float64(a) / float64(b))
}
func Wilson(k, n int) []float64 {
	if n == 0 {
		return nil
	}
	z := 1.959963984540054
	p := float64(k) / float64(n)
	nn := float64(n)
	den := 1 + z*z/nn
	center := (p + z*z/(2*nn)) / den
	radius := z * math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn)) / den
	return []float64{center - radius, center + radius}
}
func Ranking(rows []Prediction, model string) (*float64, *float64) {
	groups := map[float64][2]int{}
	pos := 0
	for _, r := range rows {
		g := groups[r.Score(model)]
		g[r.Label]++
		groups[r.Score(model)] = g
		pos += r.Label
	}
	neg := len(rows) - pos
	if pos == 0 || neg == 0 {
		return nil, nil
	}
	scores := make([]float64, 0, len(groups))
	for s := range groups {
		scores = append(scores, s)
	}
	sort.Float64s(scores)
	below, wins := 0, 0.0
	for _, s := range scores {
		g := groups[s]
		wins += float64(g[1]) * (float64(below) + float64(g[0])/2)
		below += g[0]
	}
	tp, fp, ap := 0, 0, 0.0
	for i := len(scores) - 1; i >= 0; i-- {
		g := groups[scores[i]]
		tp += g[1]
		fp += g[0]
		ap += float64(g[1]) / float64(pos) * float64(tp) / float64(tp+fp)
	}
	return ptr(wins / float64(pos*neg)), ptr(ap)
}
func Measure(rows []Prediction, model string, threshold float64) Metrics {
	m := Metrics{N: len(rows), Threshold: threshold}
	times := make([]float64, 0, len(rows))
	totalMS := 0.0
	for _, r := range rows {
		positive := r.Score(model) >= threshold
		switch {
		case positive && r.Label == 1:
			m.TP++
		case positive:
			m.FP++
		case r.Label == 1:
			m.FN++
		default:
			m.TN++
		}
		ms := r.Latency(model)
		times = append(times, ms)
		totalMS += ms
	}
	p, n := m.TP+m.FN, m.FP+m.TN
	m.Precision = ratio(m.TP, m.TP+m.FP)
	m.Recall = ratio(m.TP, p)
	m.FPR = ratio(m.FP, n)
	m.F1 = ratio(2*m.TP, 2*m.TP+m.FP+m.FN)
	m.Accuracy = ratio(m.TP+m.TN, m.N)
	if p > 0 && n > 0 {
		m.BalancedAccuracy = ptr((*m.Recall + 1 - *m.FPR) / 2)
	}
	m.AUROC, m.AveragePrecision = Ranking(rows, model)
	m.RecallCI95 = Wilson(m.TP, p)
	m.FPRCI95 = Wilson(m.FP, n)
	if len(times) > 0 {
		sort.Float64s(times)
		m.MedianMS = times[len(times)/2]
		if len(times)%2 == 0 {
			m.MedianMS = (m.MedianMS + times[len(times)/2-1]) / 2
		}
		m.P95MS = times[int(math.Ceil(.95*float64(len(times))))-1]
	}
	if totalMS > 0 {
		m.SamplesPerSecond = float64(len(times)) * 1000 / totalMS
	}
	return m
}

// Calibrate maximizes recall subject to empirical validation FPR <= 1%.
// It rejects test rows and breaks ties by lower FPR then proximity to .5.
func Calibrate(rows []Prediction, model string) (float64, error) {
	if len(rows) == 0 {
		return 0, fmt.Errorf("empty validation set")
	}
	pos, neg := 0, 0
	candidates := map[float64]bool{0: true, .5: true, math.Nextafter(1, math.Inf(1)): true}
	for _, r := range rows {
		if r.Split != "validation" {
			return 0, fmt.Errorf("calibration received non-validation row")
		}
		if r.Label == 1 {
			pos++
		} else {
			neg++
		}
		candidates[math.Nextafter(r.Score(model), math.Inf(1))] = true
	}
	if pos == 0 || neg == 0 {
		return 0, fmt.Errorf("validation requires both labels")
	}
	best, br, bf := math.Nextafter(1, math.Inf(1)), -1.0, 1.0
	for threshold := range candidates {
		tp, fp := 0, 0
		for _, r := range rows {
			if r.Score(model) >= threshold {
				if r.Label == 1 {
					tp++
				} else {
					fp++
				}
			}
		}
		rec, fpr := float64(tp)/float64(pos), float64(fp)/float64(neg)
		if fpr > .01 {
			continue
		}
		if rec > br || (rec == br && (fpr < bf || (fpr == bf && math.Abs(threshold-.5) < math.Abs(best-.5)))) {
			best, br, bf = threshold, rec, fpr
		}
	}
	return best, nil
}

// BootstrapDelta resamples complete groups, stratified by label. It measures
// paired balanced-accuracy difference at the predeclared .5 threshold.
func BootstrapDelta(rows []Prediction) (map[string]any, error) {
	return BootstrapModelDelta(rows, "ours", "deberta")
}

func BootstrapModelDelta(rows []Prediction, first, second string) (map[string]any, error) {
	type group struct{ Label, Count, Diff int }
	groups := map[string]group{}
	for _, r := range rows {
		g, ok := groups[r.Group]
		if ok && g.Label != r.Label {
			return nil, fmt.Errorf("conflicting labels in group")
		}
		g.Label = r.Label
		g.Count++
		if (r.Score(first) >= .5) == (r.Label == 1) {
			g.Diff++
		}
		if (r.Score(second) >= .5) == (r.Label == 1) {
			g.Diff--
		}
		groups[r.Group] = g
	}
	var pools [2][]group
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := groups[k]
		pools[g.Label] = append(pools[g.Label], g)
	}
	if len(pools[0]) == 0 || len(pools[1]) == 0 {
		return nil, fmt.Errorf("bootstrap requires both labels")
	}
	rng := rand.New(rand.NewSource(1))
	values := make([]float64, 2000)
	for i := range values {
		for _, pool := range pools {
			diff, count := 0, 0
			for range pool {
				g := pool[rng.Intn(len(pool))]
				diff += g.Diff
				count += g.Count
			}
			values[i] += float64(diff) / float64(count) / 2
		}
	}
	sort.Float64s(values)
	return map[string]any{"metric": first + " minus " + second + " balanced accuracy at .5", "ci95": []float64{values[49], values[1949]}, "replicates": len(values), "negative_groups": len(pools[0]), "positive_groups": len(pools[1])}, nil
}
