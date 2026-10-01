package classify

import "math"

// expf wraps math.Exp so the onnx softmax has a single implementation to
// share and the stub build still compiles the helper.
func expf(x float64) float64 { return math.Exp(x) }
