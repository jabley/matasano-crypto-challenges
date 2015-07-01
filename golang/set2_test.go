package main

import (
	"io/ioutil"
	"strings"
	"testing"
)

func TestChallenge9(t *testing.T) {
	out, err := Challenge9()
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "YELLOW SUBMARINE\u0004\u0004\u0004\u0004", out)
}

func TestChallenge10(t *testing.T) {
	out, err := Challenge10()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ioutil.ReadFile("../outputs/6.txt")
	assertEqual(t, string(expected), out)
}

func TestChallenge10RoundTrip(t *testing.T) {
	out, err := Challenge10RoundTrip()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ioutil.ReadFile("../inputs/10.txt")

	if err != nil {
		t.Fatal(err)
	}
	// the base64 encoded version we generate has no \n formatting, so we trim that from the file read
	// (which does contain \n for readability)
	expectedStr := strings.Replace(string(expected), "\n", "", -1)
	assertEqual(t, expectedStr, out)
}

