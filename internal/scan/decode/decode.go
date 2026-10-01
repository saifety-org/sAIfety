// Package decode finds encoded blobs in text and unwraps them so the scanner
// can analyze the hidden content. Decoding is bounded by the caller (depth)
// and by MaxDecoded here, and never executes anything.
//
// Supported: base64 (std/url, optionally wrapping gzip or zlib), base32,
// hex, URL encoding, \xNN and \uNNNN escape runs, HTML entities, decimal
// char-code lists (chr(105), String.fromCharCode(105, 103)), JSON-escaped
// string literals, split string literals ("ign" + "ore"), rot13.
package decode

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"html"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Candidate is one encoded region and its decoded form.
type Candidate struct {
	Encoding string // base64, base64+gzip, hex, url, escapes, entities, charcodes, json, split, rot13, ...
	Start    int    // byte offsets in the source text
	End      int
	Decoded  string
}

// MaxDecoded caps the size of one decoded layer (decompression bombs).
const MaxDecoded = 4 << 20

// MinPrintable is the share of printable runes a decoded blob must have to
// count as text and not random binary.
const MinPrintable = 0.85

var (
	reBase64   = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	reB64URL   = regexp.MustCompile(`[A-Za-z0-9_-]{40,}={0,2}`)
	reBase32   = regexp.MustCompile(`\b[A-Z2-7]{32,}={0,6}\b`)
	reHex      = regexp.MustCompile(`(?:0x)?(?:[0-9a-fA-F]{2}[\s:,]?){24,}`)
	reURLEnc   = regexp.MustCompile(`(?:%[0-9a-fA-F]{2}){8,}`)
	reEscapes  = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}|\\u\{?[0-9a-fA-F]{4,6}\}?|\\[0-7]{3}){6,}`)
	reEntities = regexp.MustCompile(`(?:&#x?[0-9a-fA-F]{1,6};|&[a-zA-Z]{2,8};){5,}`)
	reCharCode = regexp.MustCompile(`(?i)(?:chr\(\d{2,3}\)|fromCharCode\(|\bchar\(\d{2,3}\)|\b(?:\d{2,3}\s*[, ]\s*){7,}\d{2,3})`)
	reNumbers  = regexp.MustCompile(`\d{2,3}`)
	reJSONStr  = regexp.MustCompile(`"(?:[^"\\\n]|\\.){16,}"`)
	reSplitStr = regexp.MustCompile(`(?:(?:"[^"\n]{1,60}"|'[^'\n]{1,60}')\s*(?:\+|\.\.|\.|,|\||&)?\s*){3,}`)
	reLiteral  = regexp.MustCompile(`"([^"\n]*)"|'([^'\n]*)'`)
)

// Candidates returns every region of text that decodes to plausible text.
// Overlapping matches of different encodings are all returned; findings are
// attributed to the enclosing blob by the scanner.
func Candidates(text string) []Candidate {
	var out []Candidate
	add := func(enc string, m []int, decoded []byte) {
		if c, ok := decompress(decoded); ok {
			enc += "+" + c.enc
			decoded = c.data
		}
		if len(decoded) > MaxDecoded || !plausible(decoded) {
			return
		}
		out = append(out, Candidate{Encoding: enc, Start: m[0], End: m[1], Decoded: string(decoded)})
	}

	for _, m := range reBase64.FindAllStringIndex(text, -1) {
		if b, ok := tryBase64(text[m[0]:m[1]], base64.StdEncoding); ok {
			addCompressedAware(add, "base64", m, b)
		}
	}
	for _, m := range reB64URL.FindAllStringIndex(text, -1) {
		s := text[m[0]:m[1]]
		if !strings.ContainsAny(s, "-_") {
			continue // already covered by the standard alphabet
		}
		if b, ok := tryBase64(s, base64.URLEncoding); ok {
			addCompressedAware(add, "base64url", m, b)
		}
	}
	for _, m := range reBase32.FindAllStringIndex(text, -1) {
		s := text[m[0]:m[1]]
		if pad := len(s) % 8; pad != 0 && !strings.HasSuffix(s, "=") {
			s += strings.Repeat("=", 8-pad)
		}
		if b, err := base32.StdEncoding.DecodeString(s); err == nil {
			addCompressedAware(add, "base32", m, b)
		}
	}
	for _, m := range reHex.FindAllStringIndex(text, -1) {
		clean := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) || r == ':' || r == ',' {
				return -1
			}
			return r
		}, strings.TrimPrefix(text[m[0]:m[1]], "0x"))
		if len(clean)%2 != 0 {
			continue
		}
		if b, err := hex.DecodeString(clean); err == nil {
			addCompressedAware(add, "hex", m, b)
		}
	}
	for _, m := range reURLEnc.FindAllStringIndex(text, -1) {
		if s, err := url.PathUnescape(text[m[0]:m[1]]); err == nil {
			add("url", m, []byte(s))
		}
	}
	for _, m := range reEscapes.FindAllStringIndex(text, -1) {
		if s, ok := unescape(text[m[0]:m[1]]); ok {
			add("escapes", m, []byte(s))
		}
	}
	for _, m := range reEntities.FindAllStringIndex(text, -1) {
		s := html.UnescapeString(text[m[0]:m[1]])
		if s != text[m[0]:m[1]] {
			add("entities", m, []byte(s))
		}
	}
	for _, m := range charCodeRegions(text) {
		var b strings.Builder
		for _, n := range reNumbers.FindAllString(text[m[0]:m[1]], -1) {
			v, _ := strconv.Atoi(n)
			if v < 32 || v > 126 {
				continue
			}
			b.WriteByte(byte(v))
		}
		if b.Len() >= 8 {
			add("charcodes", m, []byte(b.String()))
		}
	}
	for _, m := range reJSONStr.FindAllStringIndex(text, -1) {
		lit := text[m[0]:m[1]]
		if strings.Count(lit, `\`) < 3 {
			continue // an ordinary quoted string, nothing to unwrap
		}
		if s, err := strconv.Unquote(lit); err == nil && s != strings.Trim(lit, `"`) {
			add("json", m, []byte(s))
		}
	}
	for _, m := range reSplitStr.FindAllStringIndex(text, -1) {
		var b strings.Builder
		for _, lit := range reLiteral.FindAllStringSubmatch(text[m[0]:m[1]], -1) {
			b.WriteString(lit[1] + lit[2])
		}
		if b.Len() >= 12 {
			add("split", m, []byte(b.String()))
		}
	}
	// rot13 is only tried on the whole text when it looks like garbage
	// Latin: many words but no common English/Russian stop words.
	if looksRot13(text) {
		out = append(out, Candidate{Encoding: "rot13", Start: 0, End: len(text), Decoded: rot13(text)})
	}
	return out
}

// addCompressedAware is a readability alias: add itself unwraps gzip/zlib.
func addCompressedAware(add func(string, []int, []byte), enc string, m []int, b []byte) {
	add(enc, m, b)
}

type compressed struct {
	enc  string
	data []byte
}

// decompress unwraps gzip or zlib payloads, bounded by MaxDecoded.
func decompress(b []byte) (compressed, bool) {
	if len(b) < 4 {
		return compressed{}, false
	}
	var r io.Reader
	var enc string
	switch {
	case b[0] == 0x1f && b[1] == 0x8b:
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return compressed{}, false
		}
		r, enc = gr, "gzip"
	case b[0] == 0x78 && (b[1] == 0x01 || b[1] == 0x5e || b[1] == 0x9c || b[1] == 0xda):
		zr, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return compressed{}, false
		}
		r, enc = zr, "zlib"
	default:
		return compressed{}, false
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxDecoded+1))
	if err != nil && len(data) == 0 {
		return compressed{}, false
	}
	if len(data) > MaxDecoded {
		return compressed{}, false
	}
	return compressed{enc: enc, data: data}, true
}

func tryBase64(s string, enc *base64.Encoding) ([]byte, bool) {
	if pad := len(s) % 4; pad != 0 && !strings.HasSuffix(s, "=") {
		s += strings.Repeat("=", 4-pad)
	}
	b, err := enc.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// unescape interprets \xNN, \uNNNN, \u{N...} and \NNN octal runs.
func unescape(s string) (string, bool) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		switch s[i+1] {
		case 'x':
			if i+4 <= len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 4
					continue
				}
			}
		case 'u':
			j := i + 2
			braced := j < len(s) && s[j] == '{'
			if braced {
				j++
			}
			k := j
			for k < len(s) && k-j < 6 && isHex(s[k]) {
				k++
			}
			if k > j {
				if v, err := strconv.ParseUint(s[j:k], 16, 32); err == nil {
					b.WriteRune(rune(v))
					if braced && k < len(s) && s[k] == '}' {
						k++
					}
					i = k
					continue
				}
			}
		default:
			if i+4 <= len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
					b.WriteByte(byte(v))
					i += 4
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), b.Len() > 0
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// charCodeRegions finds runs of chr()/fromCharCode()/bare numeric lists and
// extends each to the end of its statement so all numbers are captured.
func charCodeRegions(text string) [][]int {
	var out [][]int
	for _, m := range reCharCode.FindAllStringIndex(text, -1) {
		end := m[1]
		for end < len(text) && text[end] != '\n' && text[end] != ';' {
			end++
		}
		if len(out) > 0 && out[len(out)-1][1] >= m[0] {
			out[len(out)-1][1] = end
			continue
		}
		out = append(out, []int{m[0], end})
	}
	return out
}

// plausible reports whether b is mostly printable UTF-8 text.
func plausible(b []byte) bool {
	if len(b) < 8 || !utf8.Valid(b) {
		return false
	}
	var printable, total int
	for _, r := range string(b) {
		total++
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	return float64(printable)/float64(total) >= MinPrintable
}

var stopWords = []string{" the ", " and ", " you ", " is ", " to ", " и ", " не ", " в ", " на "}

func looksRot13(text string) bool {
	if len(text) < 40 || len(text) > 1<<16 {
		return false
	}
	lower := " " + strings.ToLower(text) + " "
	for _, w := range stopWords {
		if strings.Contains(lower, w) {
			return false
		}
	}
	dec := " " + strings.ToLower(rot13(text)) + " "
	hits := 0
	for _, w := range stopWords {
		if strings.Contains(dec, w) {
			hits++
		}
	}
	return hits >= 2
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}
