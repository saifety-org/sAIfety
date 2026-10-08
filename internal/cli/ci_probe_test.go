package cli

import "testing"

func TestCIGateProbe(t *testing.T) {
	t.Fatal("intentional failure: CI must block merge")
}
