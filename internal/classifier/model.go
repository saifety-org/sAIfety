package classifier

import (
	"encoding/json"
	"math"
	"sort"
)

// Model is a logistic-regression classifier over the hashed feature space.
// Score(text) returns P(attack-on-agent) in [0,1].
type Model struct {
	Dim     int       `json:"dim"`
	Weights []float64 `json:"w"`
	Bias    float64   `json:"b"`
	// TrainedAt and Metrics are metadata for provenance/debugging.
	TrainedAt string  `json:"trainedAt,omitempty"`
	Accuracy  float64 `json:"accuracy,omitempty"`
	Precision float64 `json:"precision,omitempty"`
	Recall    float64 `json:"recall,omitempty"`
}

// Predict returns the probability for an already-extracted feature vector.
func (m *Model) Predict(f map[int]float64) float64 {
	z := m.Bias
	keys := make([]int, 0, len(f))
	for i := range f {
		keys = append(keys, i)
	}
	sort.Ints(keys)
	for _, i := range keys {
		v := f[i]
		if i >= 0 && i < len(m.Weights) {
			z += m.Weights[i] * v
		}
	}
	return sigmoid(z)
}

// Score extracts features and predicts for raw text.
func (m *Model) Score(text string) float64 {
	return m.Predict(Features(text))
}

func sigmoid(z float64) float64 {
	if z < -30 {
		return 0
	}
	if z > 30 {
		return 1
	}
	return 1 / (1 + math.Exp(-z))
}

// MarshalJSON / load helpers.
func (m *Model) JSON() ([]byte, error) { return json.Marshal(m) }

// Load parses a model from JSON.
func Load(b []byte) (*Model, error) {
	var m Model
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
