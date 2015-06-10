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

func TestFixedXOR(t *testing.T) {
	out, err := FixedXOR("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "746865206b696420646f6e277420706c6179", out)
}

func assertEqual(t *testing.T, expected, actual interface{}) {
	if actual != expected {
		t.Fatalf("Expected %q: Actual: %q\n", expected, actual)
	}
}
