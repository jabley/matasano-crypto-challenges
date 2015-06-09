package main

import (
	"testing"
)

func TestConvertHexToBase64(t *testing.T) {
	s, err := Hex2Base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", s)
}
}

func assertEqual(t *testing.T, expected, actual interface{}) {
	if actual != expected {
		t.Fatalf("Expected %q: Actual: %q\n", expected, actual)
	}
}
