package normalize

import "testing"

func TestFolding(t *testing.T) {
	cases := map[string]string{
		"ignоre prеvious":                "ignore previous", // Cyrillic о, е inside Latin words
		"ᎪLERT":                          "ALERT",           // Cherokee A
		"ｉｇｎｏｒｅ":                         "ignore",          // fullwidth (NFKC)
		"\U0001d422\U0001d420\U0001d427": "ign",             // mathematical bold (NFKC)
		"привет мир":                     "привет мир",      // pure Cyrillic untouched
		"γεια σου":                       "γεια σου",        // pure Greek untouched
		"a\u200bb\u200bc":                "abc",             // zero width removed
		"“quoted”":                       "\"quoted\"",
	}
	for in, want := range cases {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}
