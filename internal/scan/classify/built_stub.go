//go:build !onnx

package classify

// Built reports whether the ONNX model backends are compiled into this
// binary. False in the default (pure-Go) build.
const Built = false
