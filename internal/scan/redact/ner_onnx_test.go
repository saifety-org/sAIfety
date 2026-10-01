//go:build onnx

package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestONNXNERRecognizesNames(t *testing.T) {
	cache := os.Getenv("SAIFETY_CACHE")
	if cache == "" {
		home, _ := os.UserHomeDir()
		cache = filepath.Join(home, ".cache", "saifety")
	}
	cfg := NERConfig{
		LibraryPath:   filepath.Join(cache, "libonnxruntime.dylib"),
		ModelPath:     filepath.Join(cache, "pii-model.onnx"),
		TokenizerPath: filepath.Join(cache, "pii-tokenizer.json"),
		ConfigPath:    filepath.Join(cache, "pii-config.json"),
	}
	for _, p := range []string{cfg.LibraryPath, cfg.ModelPath, cfg.TokenizerPath, cfg.ConfigPath} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("pii model not present (%s); run `saifety model pull`", p)
		}
	}
	ner, err := NewONNXNER(cfg)
	if err != nil {
		t.Fatalf("NewONNXNER: %v", err)
	}
	// A name with no patronymic and no nearby contact — heuristics miss it,
	// the model should catch it.
	text := "The report was prepared by Jonathan Whitfield last quarter."
	ms := ner.Recognize(text)
	found := false
	for _, m := range ms {
		val := text[m.Start:m.End]
		if strings.Contains("Jonathan Whitfield", val) && m.Kind == KindPII {
			found = true
		}
	}
	if !found {
		t.Fatalf("NER did not flag the name: %+v", ms)
	}
	// Full Find with NER attached masks it.
	out := Mask(text, Find(text, DefaultOptions.WithNER(ner)))
	if strings.Contains(out, "Jonathan") {
		t.Fatalf("name not masked with NER: %q", out)
	}

	// Multilingual: a Russian name (not in the model's training languages)
	// is still caught via the multilingual base.
	ru := "Отчёт подготовил Иван Петров вчера."
	if len(ner.Recognize(ru)) == 0 {
		t.Errorf("multilingual NER found no entity in Russian text: %q", ru)
	}
}
