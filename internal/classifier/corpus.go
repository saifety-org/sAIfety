package classifier

import (
	"bufio"
	"encoding/json"
	"os"
)

// LoadCorpus reads a JSONL file of {"text":..,"label":0|1} samples. Missing
// files yield no samples (training just uses what is available).
func LoadCorpus(path string) []Sample {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Sample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r struct {
			Text  string  `json:"text"`
			Label float64 `json:"label"`
		}
		if json.Unmarshal(line, &r) != nil || r.Text == "" {
			continue
		}
		out = append(out, Sample{Text: r.Text, Label: r.Label})
	}
	return out
}
