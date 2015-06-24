package main

import (
	"io/ioutil"
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

func TestSingleByteXORCipher(t *testing.T) {
	out, err := SingleByteXORCipher([]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "Cooking MC's like a pound of bacon", out)
}

func TestFileOfXORedContent(t *testing.T) {
	out, err := Challenge4()
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "Now that the party is jumping\n", out)
}

func TestChallenge5(t *testing.T) {
	out, err := Challenge5()
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c"+
		"2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b"+
		"2027630c692b20283165286326302e27282f", out)
}

func TestHammingDistance(t *testing.T) {
	assertEqual(t, 37, HammingDistance("this is a test", "wokka wokka!!!"))
}

func TestTransposeRequiringPadding(t *testing.T) {
	out, length := transpose([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}, 5)
	assertEqual(t, 4, length)
	assertEqual(t, []byte{1, 6, 11, 16, 2, 7, 12, 17, 3, 8, 13, 0, 4, 9, 14, 0, 5, 10, 15, 0}, out)
	out, length = transpose(out, length)
	assertEqual(t, 5, length)
	assertEqual(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 0, 0, 0}, out)
}

func TestTransposeWithoutPadding(t *testing.T) {
	out, length := transpose([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, 7)
	assertEqual(t, 2, length)
	assertEqual(t, []byte{1, 8, 2, 9, 3, 10, 4, 11, 5, 12, 6, 13, 7, 14}, out)
	out, length = transpose(out, length)
	assertEqual(t, 7, length)
	assertEqual(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, out)
}

func TestChallenge6(t *testing.T) {
	out, err := Challenge6()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ioutil.ReadFile("../outputs/6.txt")
	assertEqual(t, string(expected), out)
}

func TestChallenge7(t *testing.T) {
	out, err := Challenge7()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ioutil.ReadFile("../outputs/6.txt")
	assertEqual(t, string(expected), out)
}

func TestChallenge8(t *testing.T) {
	out, err := Challenge8()
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a", out)
}
