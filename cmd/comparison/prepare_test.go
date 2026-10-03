package main

import "testing"

func TestCanonicalAndNearDuplicates(t *testing.T) {
	if canonical(" ＡＢＣ\tStraße\n") != canonical("abc strasse") {
		t.Fatal("normalization mismatch")
	}
	index := newIndex()
	index.add("The quick brown fox jumps over the lazy dog and returns home.", "train")
	if got := index.matches("The quick brown fox jumps over the lazy dog and returns home!"); len(got) != 1 {
		t.Fatal(got)
	}
	if got := index.matches("Build the project with make."); len(got) != 0 {
		t.Fatal(got)
	}
}
