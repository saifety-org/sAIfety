package evaluation

import (
	"math"
	"testing"
)

func closeTo(t *testing.T, p *float64, want float64) {
	t.Helper()
	if p == nil || math.Abs(*p-want) > 1e-9 {
		t.Fatalf("got %v want %v", p, want)
	}
}
func TestMetricsAndTiedRanking(t *testing.T) {
	rows := []Prediction{{Sample: Sample{Label: 1}, Ours: .9}, {Sample: Sample{Label: 1}, Ours: .2}, {Sample: Sample{Label: 0}, Ours: .8}, {Sample: Sample{Label: 0}, Ours: .1}}
	m := Measure(rows, "ours", .5)
	if m.TP != 1 || m.FP != 1 || m.TN != 1 || m.FN != 1 {
		t.Fatal(m)
	}
	closeTo(t, m.Precision, .5)
	closeTo(t, m.Recall, .5)
	closeTo(t, m.FPR, .5)
	closeTo(t, m.F1, .5)
	closeTo(t, m.AUROC, .75)
	closeTo(t, m.AveragePrecision, 5.0/6)
	for i := range rows {
		rows[i].Ours = .5
	}
	m = Measure(rows, "ours", .5)
	closeTo(t, m.AUROC, .5)
	closeTo(t, m.AveragePrecision, .5)
}
func TestUndefinedMetrics(t *testing.T) {
	m := Measure([]Prediction{{Sample: Sample{Label: 0}, Ours: .1}}, "ours", .5)
	if m.Precision != nil || m.Recall != nil || m.AUROC != nil || m.BalancedAccuracy != nil {
		t.Fatal(m)
	}
	closeTo(t, m.FPR, 0)
}
func TestCalibrationRejectsTestRows(t *testing.T) {
	rows := []Prediction{{Sample: Sample{Label: 0, Split: "test"}, Ours: .1}}
	if _, err := Calibrate(rows, "ours"); err == nil {
		t.Fatal("test labels used for calibration")
	}
}
func TestCalibrationBudget(t *testing.T) {
	rows := []Prediction{{Sample: Sample{Label: 1, Split: "validation"}, Ours: .8}, {Sample: Sample{Label: 0, Split: "validation"}, Ours: .6}}
	threshold, err := Calibrate(rows, "ours")
	if err != nil {
		t.Fatal(err)
	}
	if threshold <= .6 || threshold > .8 {
		t.Fatal(threshold)
	}
	m := Measure(rows, "ours", threshold)
	closeTo(t, m.Recall, 1)
	closeTo(t, m.FPR, 0)
}
func TestBootstrapIdentical(t *testing.T) {
	rows := []Prediction{{Sample: Sample{Label: 1, Group: "a"}, Ours: .9, Deberta: .9}, {Sample: Sample{Label: 0, Group: "b"}, Ours: .1, Deberta: .1}}
	result, err := BootstrapDelta(rows)
	if err != nil {
		t.Fatal(err)
	}
	ci := result["ci95"].([]float64)
	if ci[0] != 0 || ci[1] != 0 {
		t.Fatal(ci)
	}
}
