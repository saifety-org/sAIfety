package classify

import classifier "github.com/saifety-org/prompt-injection-model"

// Trained is the default classifier: a small logistic-regression model
// trained on generated attack/benign data and embedded in the binary. It
// answers "is this text an attack on the agent?" — an instruction crafted to
// manipulate the agent, not merely text that contains a command. This is the
// discriminator that a command-danger rule cannot make.
type Trained struct{ m *classifier.Model }

// NewTrained loads the embedded model. Falls back to an error the caller can
// handle by using Lexical.
func NewTrained() (Trained, error) {
	m, err := classifier.Default()
	if err != nil {
		return Trained{}, err
	}
	return Trained{m: m}, nil
}

func (t Trained) Score(text string) float64 {
	if t.m == nil {
		return 0
	}
	return t.m.Score(text)
}
