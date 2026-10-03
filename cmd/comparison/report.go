package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alexandr-mironov/saifety/internal/evaluation"
)

func percent(v *float64) string {
	if v == nil {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", *v*100)
}
func report(dir string) {
	rows := readLines[evaluation.Prediction](filepath.Join(dir, "predictions.jsonl"))
	var meta, manifest map[string]any
	readJSON(filepath.Join(dir, "predictions.jsonl.meta.json"), &meta)
	readJSON(filepath.Join(dir, "manifest.json"), &manifest)
	training, ok := meta["training"].(map[string]any)
	if !ok || training["training_sha256"] != manifest["training_sha256"] {
		panic("model was trained on a different corpus")
	}
	if meta["inference_errors"] != float64(0) || meta["rows"] != float64(len(rows)) || meta["data_sha256"] != manifest["evaluation_sha256"] {
		panic("incomplete run or mismatched corpus")
	}
	var validation, test, nonEnglish []evaluation.Prediction
	exclusions := map[string]int{}
	splitGroups := map[string]string{}
	for _, r := range rows {
		if old, ok := splitGroups[r.Group]; ok && old != r.Split {
			panic("group crosses validation/test boundary")
		}
		splitGroups[r.Group] = r.Split
		if r.Excluded != "" {
			exclusions[r.Split+"/"+r.Language]++
			continue
		}
		if r.Language == "English" {
			if r.Split == "validation" {
				validation = append(validation, r)
			} else {
				test = append(test, r)
			}
		} else if r.Split == "test" {
			nonEnglish = append(nonEnglish, r)
		}
	}
	thresholds := map[string]float64{}
	primary := map[string]map[string]evaluation.Metrics{}
	val := map[string]evaluation.Metrics{}
	byFamily := map[string]map[string]evaluation.Metrics{}
	supplementary := map[string]evaluation.Metrics{}
	familyRows := map[string][]evaluation.Prediction{}
	for _, r := range test {
		familyRows[r.Family] = append(familyRows[r.Family], r)
	}
	for _, model := range []string{"ours", "shipped", "deberta"} {
		threshold, err := evaluation.Calibrate(validation, model)
		must(err)
		thresholds[model] = threshold
		primary[model] = map[string]evaluation.Metrics{}
		for mode, t := range map[string]float64{"default_0.5": .5, "calibrated_1pct_fpr": threshold, "runtime_0.8": .8} {
			primary[model][mode] = evaluation.Measure(test, model, t)
		}
		val[model] = evaluation.Measure(validation, model, threshold)
		supplementary[model] = evaluation.Measure(nonEnglish, model, .5)
		byFamily[model] = map[string]evaluation.Metrics{}
		for family, subset := range familyRows {
			byFamily[model][family] = evaluation.Measure(subset, model, .5)
		}
	}
	bootstrap, err := evaluation.BootstrapDelta(test)
	must(err)
	shippedBootstrap, err := evaluation.BootstrapModelDelta(test, "shipped", "deberta")
	must(err)
	writeJSON(filepath.Join(dir, "report.json"), map[string]any{"metadata": meta, "manifest": manifest, "thresholds": thresholds, "validation_rows": len(validation), "primary_test_rows": len(test), "exclusions": exclusions, "primary": primary, "validation": val, "by_family": byFamily, "supplementary": supplementary, "bootstrap": bootstrap, "shipped_vs_deberta_bootstrap": shippedBootstrap})
	var b strings.Builder
	fmt.Fprintf(&b, "# Сравнение sAIfety и DeBERTa\n\nОсновной тест: %d английских примеров (атак: %d). Калибровка: %d отдельных примеров.\n\n", len(test), primary["ours"]["default_0.5"].TP+primary["ours"]["default_0.5"].FN, len(validation))
	b.WriteString("| Режим | Модель | Порог | Precision | Recall | FPR | F1 | Balanced accuracy | TP/FN/FP/TN |\n|---|---|---:|---:|---:|---:|---:|---:|---|\n")
	for _, mode := range []string{"default_0.5", "calibrated_1pct_fpr", "runtime_0.8"} {
		for _, model := range []string{"ours", "shipped", "deberta"} {
			m := primary[model][mode]
			fmt.Fprintf(&b, "| %s | %s | %.17g | %s | %s | %s | %s | %s | %d/%d/%d/%d |\n", mode, model, m.Threshold, percent(m.Precision), percent(m.Recall), percent(m.FPR), percent(m.F1), percent(m.BalancedAccuracy), m.TP, m.FN, m.FP, m.TN)
		}
	}
	b.WriteString("\n| Модель | AUROC | Average precision | Медиана, мс | p95, мс | Примеров/с |\n|---|---:|---:|---:|---:|---:|\n")
	for _, model := range []string{"ours", "shipped", "deberta"} {
		m := primary[model]["default_0.5"]
		fmt.Fprintf(&b, "| %s | %.4f | %.4f | %.3f | %.3f | %.1f |\n", model, *m.AUROC, *m.AveragePrecision, m.MedianMS, m.P95MS, m.SamplesPerSecond)
	}
	b.WriteString("\n## Срезы при пороге 0.5\n\n| Набор | N | Recall кандидат / встроенная / DeBERTa | FPR кандидат / встроенная / DeBERTa |\n|---|---:|---|---|\n")
	families := make([]string, 0, len(familyRows))
	for f := range familyRows {
		families = append(families, f)
	}
	sort.Strings(families)
	for _, f := range families {
		a, shipped, c := byFamily["ours"][f], byFamily["shipped"][f], byFamily["deberta"][f]
		fmt.Fprintf(&b, "| %s | %d | %s / %s / %s | %s / %s / %s |\n", f, a.N, percent(a.Recall), percent(shipped.Recall), percent(c.Recall), percent(a.FPR), percent(shipped.FPR), percent(c.FPR))
	}
	a, shipped, c := supplementary["ours"], supplementary["shipped"], supplementary["deberta"]
	fmt.Fprintf(&b, "| NotInject Multilingual (дополнительно) | %d | — | %s / %s / %s |\n", a.N, percent(a.FPR), percent(shipped.FPR), percent(c.FPR))
	fmt.Fprintf(&b, "\n95%% парный групповой bootstrap-интервал разницы balanced accuracy (переобученный кандидат − DeBERTa): %v; (встроенная модель − DeBERTa): %v.\n\nИз общей выборки исключено %.0f текстов длиннее 512 токенов. Ошибок inference: 0.\n", bootstrap["ci95"], shippedBootstrap["ci95"], meta["excluded_long"])
	b.WriteString("\nПодробности, доверительные интервалы, хеши и результаты калибровки: `report.json`. Протокол: `protocol.md`. Если порог калибровки приводит к нулю срабатываний, это диагностический результат, а не рабочая рекомендация.\n\nЭто внешний benchmark по авторским меткам, а не универсальный рейтинг. Полное отсутствие пересечений с обучением DeBERTa не установлено. BIPIA содержит инструкции, чья вредоносность зависит от контекста. Многоязычный срез содержит только безопасные примеры. Скорость относится к данной CPU-реализации с batch=1, не к оптимизированному GPU/batch inference. Интервалы Wilson приведены как описательные; корреляции внутри семейств учитываются отдельно групповым bootstrap.\n\nИсточники: [PIGuard](https://github.com/leolee99/PIGuard), [DeBERTa model card](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2).\n")
	must(os.WriteFile(filepath.Join(dir, "REPORT.md"), []byte(b.String()), 0644))
	fmt.Print(b.String())
}
