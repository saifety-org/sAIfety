package classifier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCorpusStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.jsonl")
	for _, bad := range []string{"", `{"text":"hello"}`, `{"text":"hello","label":2}`, "{not json}\n", "{\"text\":\"ok\",\"label\":0}\ninvalid"} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCorpusStrict(path); err == nil {
			t.Fatalf("accepted malformed corpus %q", bad)
		}
	}
	if err := os.WriteFile(path, []byte("{\"text\":\"ok\",\"label\":0}\n{\"text\":\"attack\",\"label\":1}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rows, err := LoadCorpusStrict(path)
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %v", rows, err)
	}
}
