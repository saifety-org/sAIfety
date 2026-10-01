package redact

import "regexp"

// Names without a patronymic (e.g. "Иван Петров", "John Smith") are
// ambiguous on their own — capitalized word pairs are common in ordinary
// text. But a capitalized 2-3 word name sitting next to a phone number or an
// email is very likely a real person. contextNames flags such names using
// nearby contact matches as the disambiguator, which keeps precision high.
//
// This is the heuristic layer. A NER model (see ner.go) can supersede it for
// names that appear without any contact nearby.
const contextWindow = 48 // bytes to look on each side of a contact match

var (
	// A 2-3 token capitalized name in Cyrillic or Latin.
	nameCandidate = regexp.MustCompile(`[А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+){1,2}|[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}`)
	// Label words that precede a contact and must not be taken as a name.
	nameStop = map[string]bool{
		"Контакт": true, "Контакты": true, "Почта": true, "Телефон": true, "Тел": true,
		"Email": true, "Mail": true, "Phone": true, "Contact": true, "From": true, "To": true,
		"Кому": true, "От": true, "Заявку": true, "Ответственный": true, "Подпись": true,
	}
)

// contextNames returns name matches found next to email/phone matches.
func contextNames(text string, contacts []Match) []Match {
	var out []Match
	for _, c := range contacts {
		if c.Label != "email" && c.Label != "phone" {
			continue
		}
		out = append(out, scanWindow(text, max0(c.Start-contextWindow), c.Start)...)
		end := c.End + contextWindow
		if end > len(text) {
			end = len(text)
		}
		out = append(out, scanWindow(text, c.End, end)...)
	}
	return out
}

// scanWindow finds the name candidate nearest the contact within [lo,hi).
func scanWindow(text string, lo, hi int) []Match {
	if lo < 0 {
		lo = 0
	}
	if hi > len(text) || hi <= lo {
		return nil
	}
	seg := text[lo:hi]
	var out []Match
	for _, m := range nameCandidate.FindAllStringIndex(seg, -1) {
		start, end := lo+m[0], lo+m[1]
		// Drop a leading label word ("Контакт Иван Петров" -> "Иван Петров").
		words := splitFirstWord(text[start:end])
		if nameStop[words] {
			// re-match without the first word by advancing start
			if idx := indexAfterFirstWord(text[start:end]); idx > 0 {
				start += idx
			}
		}
		out = append(out, Match{Kind: KindPII, Label: "full_name", Start: start, End: end, Confidence: 0.7})
	}
	return out
}

func max0(x int) int {
	if x < 0 {
		return 0
	}
	return x
}

func splitFirstWord(s string) string {
	for i, r := range s {
		if r == ' ' {
			return s[:i]
		}
	}
	return s
}

func indexAfterFirstWord(s string) int {
	for i, r := range s {
		if r == ' ' {
			// skip the space too
			return i + 1
		}
	}
	return 0
}
