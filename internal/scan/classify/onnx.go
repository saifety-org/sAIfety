//go:build onnx

// Package classify — ONNX transformer backend. Built only with `-tags onnx`,
// which links the onnxruntime_go binding (cgo). The default build omits this
// file and stays pure Go with the lexical classifier.
package classify

import (
	"fmt"
	"os"
	"sync"

	"github.com/saifety-org/sAIfety/internal/onnxenv"
	"github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/pretrained"
	ort "github.com/yalue/onnxruntime_go"
)

// maxSeq is the transformer's context window; longer inputs are truncated.
const maxSeq = 512

// onnxClassifier scores text with a sequence-classification transformer
// (DeBERTa-v3 prompt-injection). It loads the ONNX Runtime library, the
// model and the tokenizer once and reuses a single session across calls.
type onnxClassifier struct {
	tk       *tokenizer.Tokenizer
	session  *ort.DynamicAdvancedSession
	injIndex int
	mu       sync.Mutex // ORT sessions are not guaranteed goroutine-safe
	tkMu     sync.Mutex // protects tokenizer configuration during token counting
}

// ONNXConfig points the classifier at its on-disk artifacts.
type ONNXConfig struct {
	LibraryPath    string
	ModelPath      string
	TokenizerPath  string
	InjectionIndex int
}

// NewONNX loads the transformer classifier. It returns an error if any
// artifact is missing so the caller can fall back to the lexical model.
func NewONNX(cfg ONNXConfig) (Classifier, error) {
	for _, p := range []string{cfg.LibraryPath, cfg.ModelPath, cfg.TokenizerPath} {
		if p == "" {
			return nil, fmt.Errorf("onnx: empty artifact path")
		}
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("onnx: %w", err)
		}
	}
	tk, err := pretrained.FromFile(cfg.TokenizerPath)
	if err != nil {
		return nil, fmt.Errorf("onnx: tokenizer: %w", err)
	}
	if err := onnxenv.Init(cfg.LibraryPath); err != nil {
		return nil, fmt.Errorf("onnx: runtime init: %w", err)
	}
	sess, err := ort.NewDynamicAdvancedSession(cfg.ModelPath,
		[]string{"input_ids", "attention_mask"}, []string{"logits"}, nil)
	if err != nil {
		return nil, fmt.Errorf("onnx: session: %w", err)
	}
	return &onnxClassifier{tk: tk, session: sess, injIndex: cfg.InjectionIndex}, nil
}

// Score retains the runtime fallback. ScoreChecked exposes tokenizer and
// inference failures to callers that need explicit error handling.
func (c *onnxClassifier) Score(text string) float64 {
	score, _ := c.ScoreChecked(text)
	return score
}

// TokenCount includes special tokens and disables truncation while counting,
// so callers can detect inputs exceeding the model's context window.
func (c *onnxClassifier) TokenCount(text string) (int, error) {
	c.tkMu.Lock()
	defer c.tkMu.Unlock()
	truncation := c.tk.GetTruncation()
	c.tk.WithTruncation(nil)
	defer c.tk.WithTruncation(truncation)
	en, err := safeEncode(c.tk, text)
	if err != nil {
		return 0, err
	}
	if en == nil || len(en.Ids) == 0 {
		return 0, fmt.Errorf("empty tokenization")
	}
	return len(en.Ids), nil
}

func (c *onnxClassifier) encode(text string) (*tokenizer.Encoding, error) {
	c.tkMu.Lock()
	defer c.tkMu.Unlock()
	return safeEncode(c.tk, text)
}

// ScoreChecked exposes inference errors; Score supplies runtime fallback.
func (c *onnxClassifier) ScoreChecked(text string) (score float64, err error) {
	defer func() {
		if r := recover(); r != nil {
			score, err = 0, fmt.Errorf("onnx inference panic: %v", r)
		}
	}()
	en, err := c.encode(text)
	if err != nil || en == nil || len(en.Ids) == 0 {
		return 0, fmt.Errorf("onnx inference failed: %v", err)
	}
	ids64 := make([]int64, 0, maxSeq)
	for i, id := range en.Ids {
		if i >= maxSeq {
			break
		}
		ids64 = append(ids64, int64(id))
	}
	n := len(ids64)
	mask := make([]int64, n)
	for i := range mask {
		mask[i] = 1
	}
	shape := ort.NewShape(1, int64(n))
	idT, err := ort.NewTensor(shape, ids64)
	if err != nil {
		return 0, fmt.Errorf("onnx inference failed: %v", err)
	}
	defer func() { _ = idT.Destroy() }() // Best-effort tensor cleanup.
	mT, err := ort.NewTensor(shape, mask)
	if err != nil {
		return 0, fmt.Errorf("onnx inference failed: %v", err)
	}
	defer func() { _ = mT.Destroy() }() // Best-effort tensor cleanup.
	outT, err := ort.NewEmptyTensor[float32](ort.NewShape(1, 2))
	if err != nil {
		return 0, fmt.Errorf("onnx inference failed: %v", err)
	}
	defer func() { _ = outT.Destroy() }() // Best-effort tensor cleanup.

	c.mu.Lock()
	err = c.session.Run([]ort.Value{idT, mT}, []ort.Value{outT})
	c.mu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("onnx inference failed: %v", err)
	}
	return softmax2(outT.GetData(), c.injIndex), nil
}

// batchSize bounds how many paragraphs are run through the model at once.
const batchSize = 16

// Scores implements BatchClassifier: it runs the model over texts in padded
// batches, which is far faster than one call per text for a deep scan.
func (c *onnxClassifier) Scores(texts []string) []float64 {
	out := make([]float64, len(texts))
	for start := 0; start < len(texts); start += batchSize {
		end := start + batchSize
		if end > len(texts) {
			end = len(texts)
		}
		c.scoreBatch(texts[start:end], out[start:end])
	}
	return out
}

// scoreBatch tokenizes a slice of texts, pads them into one [B, maxLen]
// tensor, runs the model once, and fills out with P(injection). A tokenizer
// or runtime panic leaves the affected scores at 0.
func (c *onnxClassifier) scoreBatch(texts []string, out []float64) {
	defer func() { _ = recover() }()
	encs := make([][]int64, len(texts))
	maxLen := 1
	for i, t := range texts {
		en, err := c.encode(t)
		if err != nil || en == nil || len(en.Ids) == 0 {
			continue
		}
		n := len(en.Ids)
		if n > maxSeq {
			n = maxSeq
		}
		ids := make([]int64, n)
		for j := 0; j < n; j++ {
			ids[j] = int64(en.Ids[j])
		}
		encs[i] = ids
		if n > maxLen {
			maxLen = n
		}
	}
	b := len(texts)
	ids := make([]int64, b*maxLen)
	mask := make([]int64, b*maxLen)
	for i, e := range encs {
		for j, id := range e {
			ids[i*maxLen+j] = id
			mask[i*maxLen+j] = 1
		}
	}
	shape := ort.NewShape(int64(b), int64(maxLen))
	idT, err := ort.NewTensor(shape, ids)
	if err != nil {
		return
	}
	defer func() { _ = idT.Destroy() }() // Best-effort tensor cleanup.
	mT, err := ort.NewTensor(shape, mask)
	if err != nil {
		return
	}
	defer func() { _ = mT.Destroy() }() // Best-effort tensor cleanup.
	outT, err := ort.NewEmptyTensor[float32](ort.NewShape(int64(b), 2))
	if err != nil {
		return
	}
	defer func() { _ = outT.Destroy() }() // Best-effort tensor cleanup.
	c.mu.Lock()
	err = c.session.Run([]ort.Value{idT, mT}, []ort.Value{outT})
	c.mu.Unlock()
	if err != nil {
		return
	}
	logits := outT.GetData()
	for i := 0; i < b; i++ {
		if encs[i] == nil {
			continue
		}
		out[i] = softmax2(logits[i*2:(i+1)*2], c.injIndex)
	}
}

func softmax2(logits []float32, idx int) float64 {
	if len(logits) < 2 || idx < 0 || idx >= len(logits) {
		return 0
	}
	max := logits[0]
	for _, v := range logits {
		if v > max {
			max = v
		}
	}
	var sum, want float64
	for i, v := range logits {
		e := expf(float64(v - max))
		sum += e
		if i == idx {
			want = e
		}
	}
	if sum == 0 {
		return 0
	}
	return want / sum
}
