// Package inference exposes the classifiers used by sAIfety without scan
// rules, policy, gating or automatic model downloads.
package inference

import (
	"fmt"
	"os"

	classifier "github.com/saifety-org/prompt-injection-model"
	"github.com/saifety-org/sAIfety/internal/model"
	"github.com/saifety-org/sAIfety/internal/scan/classify"
)

// Model is the native logistic-regression model and its JSON weight format.
type Model = classifier.Model

// Scorer returns the probability of an attack on the agent.
type Scorer interface{ Score(string) float64 }

// Lexical is the built-in heuristic classifier.
type Lexical = classify.Lexical

// Dim is the size of the native model's feature space.
const Dim = classifier.Dim

// Features uses exactly the feature extraction used during production inference.
func Features(text string) map[int]float64 { return classifier.Features(text) }

// Load reads native model weights from JSON.
func Load(weights []byte) (*Model, error) { return classifier.Load(weights) }

// Default returns the embedded production model, without downloads.
func Default() (*Model, error) { return classifier.Default() }

// EmbeddedSHA256 identifies the exact weight artifact shipped in the binary.
func EmbeddedSHA256() string { return classifier.EmbeddedSHA256() }

// ONNXConfig identifies local transformer and runtime artifacts.
type ONNXConfig = classify.ONNXConfig

// ONNX exposes inference errors and counts tokens without truncation.
type ONNX interface {
	Scorer
	ScoreChecked(string) (float64, error)
	TokenCount(string) (int, error)
}

// CachedONNXConfig resolves the application's cache without downloading files.
func CachedONNXConfig() (ONNXConfig, error) {
	bundle, err := model.DefaultBundle()
	if err != nil {
		return ONNXConfig{}, err
	}
	library := model.RuntimeLibPath()
	if override := os.Getenv("SAIFETY_ORT_LIB"); override != "" {
		library = override
	}
	cfg := ONNXConfig{LibraryPath: library, ModelPath: model.Path(bundle.Model), TokenizerPath: model.Path(bundle.Tokenizer), InjectionIndex: bundle.InjectionIndex}
	for _, path := range []string{cfg.LibraryPath, cfg.ModelPath, cfg.TokenizerPath} {
		if _, err := os.Stat(path); err != nil {
			return ONNXConfig{}, fmt.Errorf("ONNX artifact %s: %w", path, err)
		}
	}
	return cfg, nil
}

// NewONNX requires an onnx build and valid local artifacts. It never falls
// back to a different classifier or downloads a model.
func NewONNX(cfg ONNXConfig) (ONNX, error) {
	c, err := classify.NewONNX(cfg)
	if err != nil {
		return nil, err
	}
	checked, ok := c.(ONNX)
	if !ok {
		return nil, fmt.Errorf("ONNX backend does not support checked inference")
	}
	return checked, nil
}
