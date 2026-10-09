//go:build onnx

package classify

import "math"

// expf wraps math.Exp so the onnx softmax has a single implementation to
// share.
func expf(x float64) float64 { return math.Exp(x) }
