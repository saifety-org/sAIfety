package classify

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// Lexical is a small, self-contained classifier that scores how much a
// passage reads like an instruction aimed at an AI agent rather than prose
// or code meant for a human. It is deterministic, needs no model file and
// runs offline, so it is the default upgrade over Noop.
//
// It is intentionally a bag-of-features logistic score, not a transformer:
// the ONNX slot (see Classifier) replaces it when a model is provided. The
// weights below were hand-set from the labelled corpus now in saifety-org/lab
// and are regression-tested by the metrics harness, not learned at runtime.
type Lexical struct{}

func (Lexical) Score(text string) float64 {
	t := strings.ToLower(text)
	words := len(strings.Fields(t))
	if words < 3 {
		return 0
	}
	var score float64
	for _, f := range lexFeatures {
		if f.re.MatchString(t) {
			score += f.w
		}
	}
	// Imperative opener ("do X", "send Y") in a short passage is directive.
	if words <= 40 && imperativeOpen.MatchString(t) {
		score += 0.6
	}
	// Second-person address raises the odds it speaks to the reader-agent.
	if secondPerson.MatchString(t) {
		score += 0.4
	}
	// Code-ish passages (many symbols, few sentences) are less likely prose
	// instructions; the shell detector covers those separately.
	if symbolRatio(text) > 0.25 {
		score -= 0.5
	}
	return sigmoid(score)
}

type lexFeature struct {
	re *regexp.Regexp
	w  float64
}

var lexFeatures = compileLex(map[string]float64{
	`\b(ignore|disregard|forget|override)\b.{0,30}\b(instruction|prompt|rule|direction|context|above|previous|prior)`: 3.0,
	`(игнорир|проигнориру|забудь|отбрось).{0,30}(инструкц|правил|указан|промпт|контекст|выше|предыдущ)`:               3.0,
	`\bsystem prompt\b|\bсистемн\w* промпт`:                                                                                      1.2,
	`\byou are (now |a |an )?(dan|jailbroken|unrestricted|free from)`:                                                            2.5,
	`\b(act|behave|respond|reply) as (if|though|a |an )`:                                                                         1.0,
	`\bdo not (tell|inform|mention|reveal|warn|notify)\b.{0,20}\buser`:                                                           2.2,
	`не (говор|сообщ|рассказыв|уведомл).{0,20}пользовател`:                                                                       2.2,
	`\b(without|before) (telling|informing|asking|notifying|warning)\b.{0,15}\buser`:                                             1.6,
	`\b(secretly|silently|covertly|quietly)\b`:                                                                                   1.2,
	`\b(скрытно|незаметно|тайно)\b`:                                                                                              1.2,
	`\b(assistant|ai|agent|model|claude|gpt|llm)\b.{0,20}\b(must|should|will|shall|need to|has to)`:                              1.4,
	`\b(this|the following) (message|text|file|document|note) is (for|intended for|meant for) (the )?(ai|assistant|agent|model)`: 2.0,
	`\bnew (instructions?|rules?|directives?|task)\b`:                                                                            1.0,
	`<\s*(system|assistant|user|tool_result|instructions)\s*>`:                                                                   1.5,
	`\bexecute the (command|code|script) (below|above|following)`:                                                                1.4,
	`\b(reply|respond|answer|output) only (with|in|using)`:                                                                       0.8,
})

var (
	imperativeOpen = regexp.MustCompile(`(?i)^\s*(please\s+)?(run|execute|send|delete|remove|download|fetch|install|export|reveal|print|ignore|disregard|forget|act|pretend|respond|reply|output|do|make|set|change|replace|add|write|copy|move|выполни|запусти|отправь|удали|скачай|игнорируй|забудь|притворись|ответь|сделай|напиши|замени|добавь)\b`)
	secondPerson   = regexp.MustCompile(`(?i)\b(you|your|yourself|ты|тебе|твой|твоя|вы|ваш)\b`)
)

func compileLex(m map[string]float64) []lexFeature {
	var out []lexFeature
	for pat, w := range m {
		out = append(out, lexFeature{re: regexp.MustCompile(`(?i)` + pat), w: w})
	}
	return out
}

func symbolRatio(s string) float64 {
	if s == "" {
		return 0
	}
	var sym, total int
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		total++
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			sym++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(sym) / float64(total)
}

func sigmoid(x float64) float64 {
	// Shift so a zero raw feature score maps well below the 0.8 threshold.
	return 1 / (1 + math.Exp(-(x - 1.2)))
}
