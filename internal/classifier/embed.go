package classifier

import (
	_ "embed"
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
// trained offline (see ./gen) on generated malicious/benign samples and
// shipped in the binary, so it needs no download and runs in microseconds.
func Default() (*Model, error) {
	defaultOnce.Do(func() {
		defaultModel, defaultErr = Load(embeddedWeights)
	})
	return defaultModel, defaultErr
}
