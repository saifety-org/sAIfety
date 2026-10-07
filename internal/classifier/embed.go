package classifier

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"sync"
)

//go:embed weights.json
var embeddedWeights []byte

var (
	defaultOnce  sync.Once
	defaultModel *Model
	defaultErr   error
)

// Default returns the embedded, pre-trained attack-on-agent model. It is
// trained offline in github.com/saifety-org/lab on malicious/benign samples and
// shipped in the binary, so it needs no download and runs in microseconds.
func Default() (*Model, error) {
	defaultOnce.Do(func() {
		defaultModel, defaultErr = Load(embeddedWeights)
	})
	return defaultModel, defaultErr
}

// EmbeddedSHA256 identifies the exact embedded weight artifact.
func EmbeddedSHA256() string { return fmt.Sprintf("%x", sha256.Sum256(embeddedWeights)) }
