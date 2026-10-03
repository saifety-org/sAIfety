package classifier

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

// LoadCorpusStrict is used for experiments: missing or malformed data must
// fail the run rather than silently change the training distribution.
func LoadCorpusStrict(path string) ([]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4<<20)
	var out []Sample
	line := 0
	for sc.Scan() {
		line++
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var r struct {
			Text  string   `json:"text"`
			Label *float64 `json:"label"`
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if strings.TrimSpace(r.Text) == "" || r.Label == nil || (*r.Label != 0 && *r.Label != 1) {
			return nil, fmt.Errorf("%s:%d: invalid sample", path, line)
		}
		out = append(out, Sample{Text: r.Text, Label: *r.Label})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: empty corpus", path)
	}
	return out, nil
}
