package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPadPKCS7(t *testing.T) {
	for i := 0; i < 16; i++ {
		t.Run(fmt.Sprintf("input size %2d", i), func(t *testing.T) {
			buf := bytes.Repeat([]byte{byte('A')}, i)
			padded := padPKCS7(buf, 16)
			assertEqual(t, len(padded), 16)
		})
	}

	buf := bytes.Repeat([]byte{byte('A')}, 16)
	padded := padPKCS7(buf, 16)
	assertEqual(t, len(padded), 32)
}

func TestUnpadPKCS7(t *testing.T) {
	assertEqual(t, isPKCS7Padded(nil, 16), false)
	assertEqual(t, isPKCS7Padded([]byte{}, 16), false)

	for i := 0; i < 34; i++ {
		t.Run(fmt.Sprintf("input size %2d bytes", i), func(t *testing.T) {
			assertEqual(t, isPKCS7Padded(padPKCS7(bytes.Repeat([]byte{0x01}, i), 16), 16), true)
		})
	}
}

func TestChallenge17(t *testing.T) {
	tests := []struct {
		in       string
		expected string
	}{
		{"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", "000000Now that the party is jumping"},
		{"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", "000001With the bass kicked in and the Vega's are pumpin'"},
		{"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", "000002Quick to the point, to the point, no faking"},
		{"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", "000003Cooking MC's like a pound of bacon"},
		{"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", "000004Burning 'em, if you ain't quick and nimble"},
		{"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", "000005I go crazy when I hear a cymbal"},
		{"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", "000006And a high hat with a souped up tempo"},
		{"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", "000007I'm on a roll, it's time to go solo"},
		{"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", "000008ollin' in my five point oh"},
		{"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93", "000009ith my rag-top down so my hair can blow"},
	}

	for _, test := range tests {
		encryptMessage, isValidPadding := newCBCPaddingOracle(decodeBase64(t, test.in))
		out := encryptMessage()
		assertEqual(t, test.expected, string(unpadPKCS7(attackCBCPadding(out, isValidPadding))))
	}
}
