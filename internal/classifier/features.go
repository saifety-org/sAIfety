// Package classifier is a small, self-contained text classifier that answers
// one question: is this text an ATTACK ON THE AGENT (a prompt injection /
// jailbreak / exfiltration directive / fake system message) rather than
// ordinary project content? It is trained offline on generated malicious and
// benign samples; the learned weights ship embedded in the binary. No Python,
// no ONNX runtime — just hashed character n-grams and logistic regression,
// so it is language-agnostic (works for en/ru) and fast.
package classifier

import (
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"unicode"
)

// Dim is the feature space size (hashed n-grams). A power of two keeps the
// modulo cheap. 16384 is plenty for this vocabulary and stays small embedded.
const Dim = 16384

// ngramSizes are the character n-gram lengths hashed into the feature vector.
var ngramSizes = []int{3, 4, 5}

// Features turns text into a sparse L2-normalized feature vector represented
// as index->value. Character n-grams on a normalized, lowercased string make
// the model robust to spacing and script, and let one model serve many
// languages.
func Features(text string) map[int]float64 {
	norm := normalizeForFeatures(text)
	counts := map[int]float64{}
	runes := []rune(norm)
	for _, n := range ngramSizes {
		for i := 0; i+n <= len(runes); i++ {
			idx := hashNgram(string(runes[i : i+n]))
			counts[idx]++
		}
	}
	// Compacted view: the same text with ALL whitespace removed, so that
	// letter-spacing ("i g n o r e") and zero-width splitting collapse back
	// to the same n-grams as "ignore". Hashed with a salt into a distinct
	// region of the feature space.
	compact := []rune(removeSpaces(norm))
	for _, n := range []int{4, 5} {
		for i := 0; i+n <= len(compact); i++ {
			idx := hashNgram("cmp:" + string(compact[i:i+n]))
			counts[idx]++
		}
	}
	// A few engineered signals as dedicated dimensions (stable indices near
	// the top of the space) — cheap priors the n-grams may miss.
	signals := engineeredSignals(norm)
	signalKeys := make([]int, 0, len(signals))
	for k := range signals {
		signalKeys = append(signalKeys, k)
	}
	sort.Ints(signalKeys)
	for _, k := range signalKeys {
		v := signals[k]
		if v {
			counts[Dim-1-k] += 3 // weight signal features a bit higher
		}
	}
	// L2 normalize so length doesn't dominate.
	var sum float64
	keys := make([]int, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		v := counts[k]
		sum += v * v
	}
	if sum == 0 {
		return counts
	}
	inv := 1 / math.Sqrt(sum)
	for _, k := range keys {
		counts[k] *= inv
	}
	return counts
}

func removeSpaces(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r != ' ' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hashNgram(s string) int {
	h := fnv.New32a()
	h.Write([]byte(s))
	return int(h.Sum32() % Dim)
}

// normalizeForFeatures lowercases and collapses whitespace; it keeps letters
// of all scripts and common punctuation that carries intent (: / @ < >).
func normalizeForFeatures(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	lastSpace := false
	for _, r := range strings.ToLower(text) {
		if unicode.IsSpace(r) {
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		lastSpace = false
		b.WriteRune(r)
	}
	s := b.String()
	if len(s) > 4000 {
		s = s[:4000]
	}
	return s
}

// engineeredSignals are boolean priors keyed by a small stable index.
func engineeredSignals(norm string) map[int]bool {
	has := func(subs ...string) bool {
		for _, x := range subs {
			if strings.Contains(norm, x) {
				return true
			}
		}
		return false
	}
	return map[int]bool{
		0: has("ignore", "disregard", "forget", "игнор", "забуд", "отбрось"),
		1: has("previous instruction", "prior instruction", "above instruction", "предыдущие инструкц", "выше инструкц"),
		2: has("system prompt", "системн", "<system", "<|system", "[system]"),
		3: has("do not tell", "don't tell", "without telling", "не говори", "не сообщай", "secretly", "скрытно"),
		4: has("you are now", "you must", "ты теперь", "ты должен", "act as", "pretend"),
		5: has("api_key", "secret", "token", "password", "~/.ssh", "id_rsa", ".aws", "exfiltrate"),
		6: has("| sh", "|sh", "curl", "wget", "bash -c", "eval("),
		7: has("http://", "https://"),
		8: has("send", "upload", "post", "exfil", "отправь", "выгрузи"),
	}
}
