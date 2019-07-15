package main

import (
	"bytes"
	"crypto/aes"
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

func TestChallenge18(t *testing.T) {
	ct := decodeBase64(t, "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	key, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	fatalIfErr(t, err)
	nonce := make([]byte, 8)
	res := decryptCTR(key, ct, nonce)
	assertEqual(t, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", string(res))
}

func TestChallenge19(t *testing.T) {
	b64plaintexts := []string{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}

	key := newKey()
	println(fmt.Sprintf("Key is %v", key))

	k, err := aes.NewCipher(key)
	fatalIfErr(t, err)
	nonce := make([]byte, 8)

	var plaintexts, ciphertexts [][]byte

	for _, s := range b64plaintexts {
		pt := decodeBase64(t, s)
		ct := encryptCtr(k, pt, nonce)
		plaintexts = append(plaintexts, pt)
		ciphertexts = append(ciphertexts, ct)
	}

	// recoveredKey := findFixedNonceKeyBySubstitution(plaintexts, ciphertexts)
	// recoveredCipher, err := aes.NewCipher(recoveredKey)
	// fatalIfErr(t, err)

	// for i := range plaintexts {
	// assertEqual(t, string(plaintexts[i]), string(decryptCTR(recoveredCipher, ciphertexts[i], nonce)))
	// }
}
