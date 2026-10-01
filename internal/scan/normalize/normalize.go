// Package normalize turns raw input into canonical text so that detectors
// see one representation: NFKC-folded characters (fullwidth, mathematical
// alphanumerics, ligatures), no zero-width or bidi control runes, Unicode
// confusables mapped to ASCII where the text is trying to look Latin,
// typographic quotes and spaces folded.
//
// The invisible characters are removed here, but their presence is itself a
// signal; detect.Hidden looks at the raw text for them.
package normalize

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Code points are written numerically so that the source never contains
// invisible characters itself.
const (
	zwsp       = 0x200b // zero width space
	zwnj       = 0x200c
	zwj        = 0x200d
	wordJoiner = 0x2060
	bom        = 0xfeff
	softHyphen = 0x00ad
	mongolianV = 0x180e
	nbsp       = 0x00a0
	figureSp   = 0x2007
	narrowNbsp = 0x202f
)

// punctuation folds typographic variants that NFKC leaves alone.
var punctuation = map[rune]rune{
	nbsp: ' ', figureSp: ' ', narrowNbsp: ' ',
	0x2018: '\'', 0x2019: '\'', 0x201a: '\'', 0x201b: '\'',
	0x201c: '"', 0x201d: '"', 0x201e: '"', 0x201f: '"',
	0x2010: '-', 0x2011: '-', 0x2012: '-', 0x2013: '-', 0x2014: '-', 0x2212: '-',
}

// Invisible reports runes that carry no visible glyph and are used to hide
// or split text: zero-width joiners, bidi overrides, soft hyphen, BOM.
func Invisible(r rune) bool {
	switch r {
	case zwsp, zwnj, zwj, wordJoiner, bom, softHyphen, mongolianV:
		return true
	}
	if r >= 0x202a && r <= 0x202e { // bidi embeddings and overrides
		return true
	}
	if r >= 0x2066 && r <= 0x2069 { // bidi isolates
		return true
	}
	// Variation selectors and tag characters (used to smuggle ASCII in emoji).
	if r >= 0xfe00 && r <= 0xfe0f || r >= 0xe0000 && r <= 0xe007f {
		return true
	}
	return unicode.Is(unicode.Cf, r) && r != '\n'
}

// Text returns the canonical form of s.
func Text(s string) string {
	s = norm.NFKC.String(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, tok := range splitKeepingSeparators(s) {
		fold := ShouldFold(tok)
		for _, r := range tok {
			if Invisible(r) {
				continue
			}
			if p, ok := punctuation[r]; ok {
				b.WriteRune(p)
				continue
			}
			if fold {
				if t, ok := confusables[r]; ok {
					b.WriteString(t)
					continue
				}
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ShouldFold decides whether confusables in a token are mapped to ASCII.
// Folding everything would mangle real Cyrillic or Greek words, so a token
// is folded only when it looks like a disguised Latin word: it mixes Latin
// with another script, or it uses a script nobody writes prose in that
// happens to have Latin look-alikes (Cherokee, Lisu, Coptic, ...).
func ShouldFold(tok string) bool {
	var latin, other, rare bool
	for _, r := range tok {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			continue
		}
		switch {
		case r < 0x80:
			latin = true
		case unicode.Is(unicode.Latin, r):
			latin = true
		case isCommonScript(r):
			other = true
		default:
			rare = true
		}
	}
	return rare || (latin && other)
}

// isCommonScript reports scripts in which ordinary text is written; pure
// tokens in these are never folded.
func isCommonScript(r rune) bool {
	for _, t := range commonScripts {
		if unicode.Is(t, r) {
			return true
		}
	}
	return false
}

var commonScripts = []*unicode.RangeTable{
	unicode.Cyrillic, unicode.Greek, unicode.Armenian, unicode.Hebrew, unicode.Arabic,
	unicode.Devanagari, unicode.Bengali, unicode.Thai, unicode.Georgian,
	unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul,
}

// MixedScript reports whether a token mixes Latin with another script,
// the signature of homoglyph substitution. Used by detect.Hidden.
func MixedScript(tok string) bool {
	var latin, other bool
	for _, r := range tok {
		if !unicode.IsLetter(r) {
			continue
		}
		if r < 0x80 || unicode.Is(unicode.Latin, r) {
			latin = true
		} else {
			other = true
		}
	}
	return latin && other
}

// splitKeepingSeparators splits on whitespace but keeps the separators as
// their own tokens so the output length matches the input.
func splitKeepingSeparators(s string) []string {
	var out []string
	start := 0
	inSpace := false
	for i, r := range s {
		sp := unicode.IsSpace(r)
		if i > 0 && sp != inSpace {
			out = append(out, s[start:i])
			start = i
		}
		inSpace = sp
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
