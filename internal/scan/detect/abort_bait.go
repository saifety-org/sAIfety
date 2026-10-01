package detect

import (
	"regexp"

	"github.com/alexandr-mironov/saifety/internal/scan"
	"github.com/alexandr-mironov/saifety/internal/scan/rules"
)

// AbortBait finds "refusal tripwire" content: passages planted to make a
// safety-tuned reviewing agent disengage, refuse, or stop reading, so that a
// malicious payload placed right after goes unreviewed. It exploits the
// reviewer's safety training, not its logic.
//
// The mere mention of a sensitive topic is not enough (a security or research
// repo may discuss it legitimately). A finding needs a combination:
//   - reviewer-directed abort framing ("stop analyzing", "refuse to continue"), or
//   - a high-refusal topic that is incongruous with the surrounding material
//     (planted in code/config, or wrapped in a comment next to code).
//
// Topics are matched at the level of "this is a refusal-triggering subject"
// only — no operational detail. The detector never needs, and must not carry,
// how-to content.
type AbortBait struct{}

func (AbortBait) Name() string { return "abort_bait" }

// abortFraming: text aimed at the reviewer to make it stop or refuse.
var abortFraming = regexp.MustCompile(`(?i)(` +
	`stop (reading|scanning|analy[sz]ing|reviewing|processing)|` +
	`do not (read|scan|analy[sz]e|review|continue|proceed)|` +
	`(cease|halt|abort) (your )?(analysis|review|scan|reading)|` +
	`refuse to (continue|proceed|analy[sz]e|help|assist)|` +
	`you (must|should) (stop|refuse|decline|not continue)|` +
	`this (project|code|repository|repo|work) is (illegal|immoral|unethical|forbidden|prohibited)|` +
	`прекрати(те)? (чтение|сканирование|анализ|проверку)|` +
	`не (читай|сканируй|анализируй|продолжай)( дальше)?|` +
	`(останови|прекрати)(те)? (анализ|проверку|сканирование)|` +
	`(ты|вы) (должен|должны|обязан) (остановиться|отказаться|прекратить)|` +
	`откажись (продолжать|помогать|анализировать)` +
	`)`)

// refusalTopic: subjects that reliably trigger a safety-tuned model to
// disengage. Topic-level only.
var refusalTopic = regexp.MustCompile(`(?i)\b(` +
	`weapons? of mass destruction|wmd|` +
	`bio(logical)?[- ]?weapons?|bioweapons?|` +
	`chemical weapons?|nerve agents?|` +
	`nuclear (weapons?|bombs?|device)|dirty bombs?|` +
	`(synthesi[sz]e|weaponi[sz]e|culture) (a )?(pathogens?|viruses?|nerve agents?|anthrax|smallpox|sarin|ricin)|` +
	`mass[- ]?casualt(y|ies)|bioterror(ism)?|` +
	`child (sexual abuse|abuse material)|csam|` +
	`оруж(ие|ия) массового поражения|` +
	`био(логическо(е|го))?[- ]?оруж(ие|ия)|` +
	`химическо(е|го) оруж(ие|ия)|нервно-паралитическ|` +
	`ядерн(ое|ого) оруж(ие|ия)|` +
	`синтез (патогена|вируса|отравляющего)` +
	`)\b`)

// reviewerAddressed: content that speaks to "the AI/assistant/agent",
// strengthening the read that a passage targets the reviewer.
var reviewerAddressed = regexp.MustCompile(`(?i)\b(ai|assistant|agent|model|claude|gpt|llm|reviewer|scanner|ассистент|агент|модел|сканер|проверяющ)`)

func (AbortBait) Detect(doc *scan.Document, text string) []scan.Finding {
	var out []scan.Finding
	framing := abortFraming.FindAllStringIndex(text, -1)
	topics := refusalTopic.FindAllStringIndex(text, -1)
	if len(framing) == 0 && len(topics) == 0 {
		return nil
	}

	docHasFraming := len(framing) > 0

	for _, m := range framing {
		conf := 0.75
		if reviewerAddressed.MatchString(window(text, m[0], m[1], 40)) {
			conf = 0.9
		}
		out = append(out, scan.Finding{
			Category: scan.CatAbortBait, Level: rules.Impact[scan.CatAbortBait], Confidence: conf,
			Span:    scan.Span{Start: m[0], End: m[1]},
			Message: "content directs the reviewer to stop or refuse; continue analysis",
		})
	}
	for _, m := range topics {
		// The discriminator is reviewer-directed abort framing, not the topic
		// itself: a security or research file may mention these subjects
		// legitimately. A topic is bait only when abort framing accompanies
		// it, or when it sits somewhere a topic has no business at all.
		conf := 0.0
		switch {
		case abortFraming.MatchString(window(text, m[0], m[1], 160)):
			conf = 0.9 // topic + nearby abort framing = classic bait
		case docHasFraming:
			conf = 0.7 // framing elsewhere in the same source; payload split off
		case doc.Kind == scan.KindAgentConfig:
			conf = 0.6 // a weapons topic inside an agent config is anomalous
		default:
			conf = 0.0 // a bare topic mention is content, not bait
		}
		if conf < 0.4 {
			continue
		}
		out = append(out, scan.Finding{
			Category: scan.CatAbortBait, Level: rules.Impact[scan.CatAbortBait], Confidence: conf,
			Span:    scan.Span{Start: m[0], End: m[1]},
			Message: "refusal-triggering topic positioned to make the reviewer disengage; a payload may follow",
		})
	}
	return out
}

// window returns the substring around [start,end) padded by pad bytes.
func window(text string, start, end, pad int) string {
	s := start - pad
	if s < 0 {
		s = 0
	}
	e := end + pad
	if e > len(text) {
		e = len(text)
	}
	return text[s:e]
}
