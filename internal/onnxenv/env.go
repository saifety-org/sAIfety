//go:build onnx

// Package onnxenv centralizes ONNX Runtime initialization. The runtime can be
// initialized only once per process, so every model backend (the injection
// classifier and the PII NER) must share one Init call rather than each
// calling InitializeEnvironment. Built only with -tags onnx.
package onnxenv

import (
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

var (
	once sync.Once
	err  error
)

// Init sets the shared library path and initializes the runtime once. The
// first caller's libPath wins; later calls are no-ops and return the first
// result. Safe to call from multiple backends.
func Init(libPath string) error {
	once.Do(func() {
		ort.SetSharedLibraryPath(libPath)
		err = ort.InitializeEnvironment()
	})
	return err
}
