//go:build !onnx

package classify

import "fmt"

// ONNXConfig mirrors the onnx-build type so callers compile without the tag.
type ONNXConfig struct {
	LibraryPath    string
	ModelPath      string
	TokenizerPath  string
	InjectionIndex int
}

// NewONNX is unavailable unless the binary is built with `-tags onnx`.
func NewONNX(ONNXConfig) (Classifier, error) {
	return nil, fmt.Errorf("onnx classifier not built in; rebuild with: go build -tags onnx")
}
