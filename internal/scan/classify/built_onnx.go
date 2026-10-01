//go:build onnx

package classify

// Built reports whether the ONNX model backends are compiled into this
// binary. True only with -tags onnx.
const Built = true
