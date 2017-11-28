package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"
)

func TestChallenge1(t *testing.T) {
	s, err := hex2Base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	fatalIfErr(t, err)
	assertEqual(t, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", s)
}

func TestChallenge2(t *testing.T) {
	out := xor(
		decodeHex(t, "1c0111001f010100061a024b53535009181c"),
		decodeHex(t, "686974207468652062756c6c277320657965"))
	assertEqual(t, decodeHex(t, "746865206b696420646f6e277420706c6179"), out)
}

func TestChallenge3(t *testing.T) {
	out, _, _ := findSingleXORKey(decodeHex(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	assertEqual(t, "Cooking MC's like a pound of bacon", string(out))
}

func TestChallenge4(t *testing.T) {
	in := string(readFile(t, "../inputs/4.txt"))
	bestScore := 0
	var out []byte

	for _, hs := range strings.Split(in, "\n") {
		candidate, score, _ := findSingleXORKey(decodeHex(t, hs))
		if score > bestScore {
			bestScore = score
			out = candidate
		}
	}
	assertEqual(t, "Now that the party is jumping\n", string(out))
}

func TestChallenge5(t *testing.T) {
	in := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte{'I', 'C', 'E'}
	dst := repeatingXOR(in, key)
	assertEqual(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c"+
		"2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b"+
		"2027630c692b20283165286326302e27282f", hex.EncodeToString(dst))
}

func TestChallenge6(t *testing.T) {
	assertEqual(t, 37, hammingDistance("this is a test", "wokka wokka!!!"))
	text := decodeBase64(t, string(readFile(t, "../inputs/6.txt")))
	keySize := findKeySize(text)
	key := findRepeatingXORKey(text, keySize)
	out := repeatingXOR(text, key)

	expected := readFile(t, "../outputs/6.txt")
	assertEqual(t, string(expected), string(out))
}

func TestChallenge7(t *testing.T) {
	in := decodeBase64(t, string(readFile(t, "../inputs/7.txt")))
	b, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	fatalIfErr(t, err)
	blockCipher := newAESECBBlockCipher(b)
	out, err := blockCipher.decrypt(in)
	fatalIfErr(t, err)
	expected := readFile(t, "../outputs/6.txt")
	assertEqual(t, string(expected), string(out))
}

func TestChallenge8(t *testing.T) {
	all := string(readFile(t, "../inputs/8.txt"))
	for i, hs := range strings.Split(all, "\n") {
		if detectECB(decodeHex(t, hs)) {
			assertEqual(t, 133, i+1)
		}
	}
}

func assertEqual(t *testing.T, expected, actual interface{}) {
	t.Helper()
	if expected == nil || actual == nil {

		if actual != expected {
			fail(t, expected, actual)
		}
		return
	}
	if !reflect.DeepEqual(expected, actual) {
		fail(t, expected, actual)
	}
}

func decodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal("failed to decode base64:", s)
	}
	return v
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	v, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("failed to decode hex:", s)
	}
	return v
}

func fail(t *testing.T, expected, actual interface{}) {
	t.Helper()
	t.Fatalf("Expected\n%#v\nActual:\n%#v\n", expected, actual)
}

func fatalIfErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatal("failed to read file:", err)
	}
	return data
}
