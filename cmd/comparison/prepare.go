package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alexandr-mironov/saifety/internal/classifier"
	"github.com/alexandr-mironov/saifety/internal/evaluation"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const revision = "1b5751e88bf7475acbedfc8eda795ce060307c84"

var files = []string{"BIPIA_code.json", "BIPIA_text.json", "NotInject_one.json", "NotInject_two.json", "NotInject_three.json", "wildguard.json"}

var sourceHashes = map[string]string{
	"BIPIA_code.json":      "892545c5aaec0645b1ded65dc7816b3d70e9ef4eadcba2301a7a3db93676b6e0",
	"BIPIA_text.json":      "75750e7b4e8b34e8f9d88d89b357aeaaf02bd07f9e493ccd37eda74a0cd7c7f8",
	"NotInject_one.json":   "69b535596d95102424e9c5946944feb4f2d596687eb8213f2ecad75478e5ffdd",
	"NotInject_two.json":   "6043d94e75b48d8e7682d25dc79eaf45359e1e561ce520e3b8fd5625a91060c6",
	"NotInject_three.json": "ef01eff0d761d2e34571b3fdbcec08c30cd93efe8d0e1a2eb5c2baeb1873b070",
	"wildguard.json":       "d884fc834a5a8081a423c49effb7aeb7977e991c1e3e7fb58e0285630d550bad",
}

func canonical(text string) string {
	return strings.Join(strings.Fields(cases.Fold().String(norm.NFKC.String(text))), " ")
}
func digest(text string) string { return hashBytes([]byte(text)) }
func shingles(text string) map[string]bool {
	s := []rune(canonical(text))
	out := map[string]bool{}
	if len(s) < 5 {
		out[string(s)] = true
		return out
	}
	for i := 0; i+5 <= len(s); i++ {
		out[string(s[i:i+5])] = true
	}
	return out
}

type similarityIndex struct {
	lengths  []int
	ids      []string
	inverted map[string][]int
}

func newIndex() *similarityIndex { return &similarityIndex{inverted: map[string][]int{}} }
func (x *similarityIndex) matches(text string) []string {
	grams := shingles(text)
	counts := map[int]int{}
	for g := range grams {
		for _, i := range x.inverted[g] {
			counts[i]++
		}
	}
	var out []string
	for i, count := range counts {
		if float64(count)/float64(len(grams)+x.lengths[i]-count) >= .8 {
			out = append(out, x.ids[i])
		}
	}
	sort.Strings(out)
	return out
}
func (x *similarityIndex) add(text, id string) {
	grams := shingles(text)
	i := len(x.ids)
	x.ids = append(x.ids, id)
	x.lengths = append(x.lengths, len(grams))
	for g := range grams {
		x.inverted[g] = append(x.inverted[g], i)
	}
}

type trainRow struct {
	Text  string  `json:"text"`
	Label float64 `json:"label"`
}

func prepare(dir string) {
	var benchmark []evaluation.Sample
	provenance := map[string]any{}
	client := http.Client{Timeout: 60 * time.Second}
	for _, name := range files {
		path := filepath.Join(dir, "raw", name)
		url := "https://raw.githubusercontent.com/leolee99/PIGuard/" + revision + "/datasets/" + name
		b, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			resp, e := client.Get(url)
			must(e)
			if resp.StatusCode != 200 {
				resp.Body.Close()
				panic(fmt.Sprintf("%s: HTTP %d", name, resp.StatusCode))
			}
			b, err = io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			resp.Body.Close()
			must(err)
			must(os.WriteFile(path, b, 0644))
		} else {
			must(err)
		}
		if hashBytes(b) != sourceHashes[name] {
			panic("source checksum mismatch: " + name)
		}
		provenance[name] = map[string]string{"url": url, "sha256": hashBytes(b)}
		add := func(text string, label int, category string) {
			if strings.TrimSpace(text) == "" {
				panic("empty external sample")
			}
			language := "English"
			if category == "Multilingual" || category == "Multilingual Queries" {
				language = "non-English"
			}
			benchmark = append(benchmark, evaluation.Sample{ID: digest(canonical(text)), Text: text, Label: label, Family: strings.TrimSuffix(name, ".json"), Category: category, Language: language})
		}
		if strings.HasPrefix(name, "BIPIA") {
			var data map[string][]string
			must(json.Unmarshal(b, &data))
			categories := make([]string, 0, len(data))
			for k := range data {
				categories = append(categories, k)
			}
			sort.Strings(categories)
			for _, category := range categories {
				for _, text := range data[category] {
					add(text, 1, category)
				}
			}
		} else {
			var data []struct {
				Prompt   string `json:"prompt"`
				Category string `json:"category"`
				Label    int    `json:"label"`
			}
			must(json.Unmarshal(b, &data))
			for _, r := range data {
				if r.Label != 0 {
					panic("expected benign source")
				}
				if r.Category == "" {
					r.Category = "chat"
				}
				add(r.Prompt, 0, r.Category)
			}
		}
	}
	unique := map[string]evaluation.Sample{}
	for _, r := range benchmark {
		if previous, ok := unique[r.ID]; ok {
			if previous.Label != r.Label {
				panic("conflicting benchmark labels")
			}
		} else {
			unique[r.ID] = r
		}
	}
	benchmark = nil
	for _, r := range unique {
		benchmark = append(benchmark, r)
	}
	sort.Slice(benchmark, func(i, j int) bool { return benchmark[i].ID < benchmark[j].ID })
	index := newIndex()
	parents := map[string]string{}
	for _, r := range benchmark {
		parents[r.ID] = r.ID
	}
	var root func(string) string
	root = func(x string) string {
		if parents[x] != x {
			parents[x] = root(parents[x])
		}
		return parents[x]
	}
	union := func(a, b string) {
		a, b = root(a), root(b)
		if a < b {
			parents[b] = a
		} else {
			parents[a] = b
		}
	}
	for _, r := range benchmark {
		for _, other := range index.matches(r.Text) {
			union(r.ID, other)
		}
		index.add(r.Text, r.ID)
	}
	families := map[string]string{}
	for _, r := range benchmark {
		if strings.HasPrefix(r.Family, "BIPIA") {
			family := r.Family + "/" + r.Category
			if other, ok := families[family]; ok {
				union(r.ID, other)
			}
			families[family] = r.ID
		}
	}
	splits := map[string]int{}
	for i := range benchmark {
		r := &benchmark[i]
		r.Group = root(r.ID)
		hash := digest("saifety-eval-v1:" + r.Group)
		n, err := strconv.ParseUint(hash[:8], 16, 32)
		must(err)
		r.Split = "test"
		if n%4 == 0 {
			r.Split = "validation"
		}
		splits[fmt.Sprintf("%s/%s/%d", r.Split, r.Language, r.Label)]++
	}
	rawTrain := classifier.Generate(1)
	trainingSources := map[string]string{"synthetic_generator": "internal/classifier/data.go; seed=1", "synthetic_generator_sha256": hashFile("internal/classifier/data.go")}
	for _, path := range []string{"internal/classifier/data/external.jsonl", "internal/classifier/data/local_benign.jsonl"} {
		rows, err := classifier.LoadCorpusStrict(path)
		must(err)
		rawTrain = append(rawTrain, rows...)
		trainingSources[path] = hashFile(path)
	}
	labels := map[string]int{}
	for _, r := range rawTrain {
		labels[canonical(r.Text)] |= 1 << int(r.Label)
	}
	var train []trainRow
	seen := map[string]bool{}
	excluded := map[string]int{}
	for _, r := range rawTrain {
		k := canonical(r.Text)
		switch {
		case labels[k] == 3:
			excluded["conflicting_label_rows"]++
		case seen[k]:
			excluded["duplicate_rows"]++
		case len(index.matches(r.Text)) > 0:
			excluded["benchmark_overlap_rows"]++
		default:
			seen[k] = true
			train = append(train, trainRow{r.Text, r.Label})
		}
	}
	sort.Slice(train, func(i, j int) bool { return digest(canonical(train[i].Text)) < digest(canonical(train[j].Text)) })
	manifest := map[string]any{"revision": revision, "sources": provenance, "training_input_sha256": trainingSources, "near_duplicate_metric": "NFKC/casefold/whitespace normalized character 5-gram Jaccard >= 0.8", "excluded_training": excluded, "train_rows": len(train), "raw_train_rows": len(rawTrain), "benchmark_rows": len(benchmark), "training_sha256": writeLines(filepath.Join(dir, "train.jsonl"), train), "evaluation_sha256": writeLines(filepath.Join(dir, "evaluation.jsonl"), benchmark), "splits": splits}
	writeJSON(filepath.Join(dir, "manifest.json"), manifest)
	fmt.Printf("train=%d (raw=%d), benchmark=%d, exclusions=%v\nsplits=%v\n", len(train), len(rawTrain), len(benchmark), excluded, splits)
}
