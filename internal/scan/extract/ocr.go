package extract

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// OCR turns image pixels into text. Implementations are external engines;
// none is bundled, and OCR is off unless enabled explicitly because it is
// slow and its output is noisy.
type OCR interface {
	// Recognize returns the text found in the image, or "" when none.
	Recognize(ctx context.Context, name string, data []byte) (string, error)
	// Available reports whether the engine can run on this machine.
	Available() bool
}

// Tesseract shells out to the tesseract CLI. Languages default to eng+rus.
type Tesseract struct {
	Binary    string // default "tesseract"
	Languages string // default "eng+rus"
	Timeout   time.Duration
}

func (t Tesseract) bin() string {
	if t.Binary != "" {
		return t.Binary
	}
	return "tesseract"
}

func (t Tesseract) Available() bool {
	_, err := exec.LookPath(t.bin())
	return err == nil
}

func (t Tesseract) Recognize(ctx context.Context, name string, data []byte) (string, error) {
	timeout := t.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tmp, err := os.CreateTemp("", "saifety-ocr-*"+filepath.Ext(name))
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // Best-effort cleanup.
	if _, err := tmp.Write(data); err != nil {
		return "", err
	}
	_ = tmp.Close()
	langs := t.Languages
	if langs == "" {
		langs = "eng+rus"
	}
	cmd := exec.CommandContext(ctx, t.bin(), tmp.Name(), "-", "-l", langs, "--psm", "6")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}
