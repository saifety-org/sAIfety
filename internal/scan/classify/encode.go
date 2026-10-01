//go:build onnx

package classify

import "github.com/sugarme/tokenizer"

// safeEncode wraps EncodeSingle so a tokenizer panic (a known issue in some
// tokenizer builds on certain inputs) becomes an error instead of crashing.
func safeEncode(tk *tokenizer.Tokenizer, text string) (en *tokenizer.Encoding, err error) {
	defer func() {
		if r := recover(); r != nil {
			en, err = nil, errTokenizer
		}
	}()
	e, err := tk.EncodeSingle(text, true)
	if err != nil {
		return nil, err
	}
	return e, nil
}

var errTokenizer = tokenizerError("tokenizer panicked")

type tokenizerError string

func (e tokenizerError) Error() string { return string(e) }
