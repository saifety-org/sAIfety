package redact

// NER is an optional named-entity recognizer for personal data. It catches
// what the pattern and context layers miss — chiefly names that appear with
// no patronymic and no nearby contact — using a small token-classification
// model (a BERT/DistilBERT fine-tuned for PII). It is offline and pluggable:
// the default build ships without one, and the onnx build loads a model.
type NER interface {
	// Recognize returns PII spans found by the model.
	Recognize(text string) []Match
}

// WithNER returns a copy of opts using the given recognizer.
func (o Options) WithNER(n NER) Options {
	o.ner = n
	return o
}
