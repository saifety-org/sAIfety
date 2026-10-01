// Package redact finds and masks secrets, credentials and personal data in
// text. It serves two jobs: producing findings for the scanner, and masking
// the data before it reaches the agent (the "обезличивание" block from the
// project idea). Everything is offline: curated patterns plus Shannon
// entropy, no network verification.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Kind labels what a match is, and drives the placeholder it is masked with.
type Kind string

const (
	KindSecret Kind = "secret" // API keys, tokens, private keys
	KindPII    Kind = "pii"    // emails, phones, cards, IPs
	KindAuth   Kind = "auth"   // Authorization headers, credentials in URLs
	KindCustom Kind = "custom" // matched a user keyword denylist entry
)

// Match is one detected span.
type Match struct {
	Kind       Kind
	Label      string  // e.g. "aws_access_key", "email", "jwt"
	Start, End int     // byte offsets
	Confidence float64 // 0..1
}

// Options tune detection and masking.
type Options struct {
	// Keywords are extra literal strings to redact (case-insensitive).
	Keywords []string
	// Allowlist are substrings that must never be redacted even if matched.
	Allowlist []string
	// MaskIP includes IP addresses as PII.
	MaskIP bool
	// MinEntropy is the Shannon-entropy threshold for generic high-entropy
	// token detection (bits per char). 0 disables entropy scanning.
	MinEntropy float64
	// ner, when set, is an optional model-based recognizer (see WithNER).
	ner NER
}

// DefaultOptions enables the standard secret/PII set with entropy off (too
// noisy without tuning) and IP masking on.
var DefaultOptions = Options{MaskIP: true, MinEntropy: 0}

// Find returns all matches in text, sorted by position, de-overlapped so a
// secret isn't also reported as generic entropy.
func Find(text string, opts Options) []Match {
	var out []Match
	for _, p := range patterns {
		if p.kind == KindPII && p.label == "ip" && !opts.MaskIP {
			continue
		}
		for _, m := range p.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := m[0], m[1]
			if len(m) >= 4 && m[2] >= 0 { // capture group 1 = the sensitive part
				s, e = m[2], m[3]
			}
			if p.validate != nil && !p.validate(text[s:e]) {
				continue
			}
			out = append(out, Match{Kind: p.kind, Label: p.label, Start: s, End: e, Confidence: p.conf})
		}
	}
	for _, kw := range opts.Keywords {
		if kw == "" {
			continue
		}
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(kw))
		for _, m := range re.FindAllStringIndex(text, -1) {
			out = append(out, Match{Kind: KindCustom, Label: "keyword", Start: m[0], End: m[1], Confidence: 1})
		}
	}
	if opts.MinEntropy > 0 {
		out = append(out, entropyMatches(text, opts.MinEntropy)...)
	}
	// Context layer: names without a patronymic, disambiguated by a nearby
	// phone/email. Runs on the matches found so far.
	out = append(out, contextNames(text, out)...)
	// Model layer: a PII NER model catches remaining personal data.
	if opts.ner != nil {
		out = append(out, opts.ner.Recognize(text)...)
	}
	out = filterAllowlisted(text, out, opts.Allowlist)
	return dedupe(out)
}

// Mask replaces every match with a typed placeholder, outermost first, so the
// agent sees structure without the sensitive value.
func Mask(text string, matches []Match) string {
	if len(matches) == 0 {
		return text
	}
	ms := append([]Match(nil), matches...)
	sort.Slice(ms, func(i, j int) bool { return ms[i].Start < ms[j].Start })
	var b strings.Builder
	pos := 0
	for _, m := range ms {
		if m.Start < pos || m.Start < 0 || m.End > len(text) || m.End <= m.Start {
			continue
		}
		b.WriteString(text[pos:m.Start])
		b.WriteString(maskValue(m.Label, text[m.Start:m.End]))
		pos = m.End
	}
	b.WriteString(text[pos:])
	return b.String()
}

func filterAllowlisted(text string, in []Match, allow []string) []Match {
	if len(allow) == 0 {
		return in
	}
	var out []Match
	for _, m := range in {
		val := text[m.Start:m.End]
		keep := true
		for _, a := range allow {
			if a != "" && strings.Contains(val, a) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, m)
		}
	}
	return out
}

// dedupe drops a match fully contained in another (prefer the more specific,
// higher-confidence one).
func dedupe(in []Match) []Match {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Start != in[j].Start {
			return in[i].Start < in[j].Start
		}
		return in[i].End > in[j].End
	})
	var out []Match
	for _, m := range in {
		covered := false
		for _, k := range out {
			if m.Start >= k.Start && m.End <= k.End {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// maskValue produces the masked form of one value. Personal data keeps a few
// edge characters so the record stays readable, with a single "*" for the
// hidden middle. Secrets and credentials are never shown partially.
func maskValue(label, val string) string {
	switch label {
	case "phone":
		return maskPhone(val)
	case "ip":
		return maskIPv4(val)
	case "full_name":
		return maskName(val)
	case "email":
		return maskEmail(val)
	case "credit_card":
		return maskCard(val)
	default:
		// secrets, auth, tokens, keywords, high-entropy, and any other type
		// are fully hidden — a partial secret is still a leak.
		return "[REDACTED:" + label + "]"
	}
}

// maskPhone keeps a leading "+" (if present), the first 4 digits and the last
// 2, hiding the middle with one "*": +7 916 555-01-32 -> +7916*32.
func maskPhone(val string) string {
	plus := strings.HasPrefix(strings.TrimSpace(val), "+")
	var digits []rune
	for _, r := range val {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
		}
	}
	if len(digits) < 6 {
		return "*"
	}
	head := string(digits[:4])
	tail := string(digits[len(digits)-2:])
	if plus {
		head = "+" + head
	}
	return head + "*" + tail
}

// maskIPv4 keeps the first and last octet: 192.168.0.1 -> 192.*.*.1.
func maskIPv4(val string) string {
	parts := strings.Split(val, ".")
	if len(parts) != 4 {
		return "*"
	}
	return parts[0] + ".*.*." + parts[3]
}

// maskName keeps 2 letters of the first part and 1 letter of each other part,
// each followed by a single "*": Иванов Иван Иванович -> Ив* И* И*.
func maskName(val string) string {
	fields := strings.Fields(val)
	out := make([]string, 0, len(fields))
	for i, f := range fields {
		rs := []rune(f)
		keep := 1
		if i == 0 {
			keep = 2
		}
		if len(rs) <= keep {
			out = append(out, f)
			continue
		}
		out = append(out, string(rs[:keep])+"*")
	}
	return strings.Join(out, " ")
}

// maskEmail keeps the first character of the local part and the domain:
// john.doe@example.com -> j*@example.com.
func maskEmail(val string) string {
	at := strings.IndexByte(val, '@')
	if at <= 0 {
		return "*"
	}
	local := []rune(val[:at])
	return string(local[:1]) + "*" + val[at:]
}

// maskCard keeps the last 4 digits: 4111 1111 1111 1111 -> *1111.
func maskCard(val string) string {
	var digits []rune
	for _, r := range val {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
		}
	}
	if len(digits) < 4 {
		return "*"
	}
	return "*" + string(digits[len(digits)-4:])
}
