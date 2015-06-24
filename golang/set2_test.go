package main

import "testing"

func TestChallenge9(t *testing.T) {
	out, err := Challenge9()
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "YELLOW SUBMARINE\u0004\u0004\u0004\u0004", out)
}
