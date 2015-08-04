package main

import (
	"crypto/aes"
	"encoding/base64"
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

func TestRoundTripECB(t *testing.T) {
	out, err := RoundTripECB()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ioutil.ReadFile("../inputs/7.txt")

	if err != nil {
		t.Fatal(err)
	}
	// the base64 encoded version we generate has no \n formatting, so we trim that from the file read
	// (which does contain \n for readability)
	expectedStr := strings.Replace(string(expected), "\n", "", -1)
	assertEqual(t, expectedStr, out)
}

func TestChallenge11(t *testing.T) {
	plainText := createECBDetectingPlainText(aes.BlockSize)
	encryptionOracle := generateEncryptionOracle()
	cipherText, mode := encryptionOracle(plainText)
	detectedMode := sniffEncryptionMode(cipherText)
	assertEqual(t, mode, detectedMode)
}

func TestBlockSizeInfoForDifferentSuffixLengths(t *testing.T) {
	oracleFn := newECBEncryptionOracle(newKey(), []byte{}, []byte{})

	createSuffixTestFixture := func(suffixLength, inputSizeToGetFullPadding int) SuffixTestFixture {
		return SuffixTestFixture{
			suffixLength: suffixLength,
			blockSizeInfo: BlockSizeInfo{
				inputSizeToGetFullPadding: inputSizeToGetFullPadding,
				blockSize:                 aes.BlockSize,
			},
		}
	}

	fixtures := []SuffixTestFixture{
		createSuffixTestFixture(0, aes.BlockSize),
		createSuffixTestFixture(1, aes.BlockSize-1),
		createSuffixTestFixture(2, aes.BlockSize-2),
		createSuffixTestFixture(3, aes.BlockSize-3),
		createSuffixTestFixture(4, aes.BlockSize-4),
		createSuffixTestFixture(5, aes.BlockSize-5),
		createSuffixTestFixture(6, aes.BlockSize-6),
		createSuffixTestFixture(7, aes.BlockSize-7),
		createSuffixTestFixture(8, aes.BlockSize-8),
		createSuffixTestFixture(9, aes.BlockSize-9),
		createSuffixTestFixture(10, aes.BlockSize-10),
		createSuffixTestFixture(11, aes.BlockSize-11),
		createSuffixTestFixture(12, aes.BlockSize-12),
		createSuffixTestFixture(13, aes.BlockSize-13),
		createSuffixTestFixture(14, aes.BlockSize-14),
		createSuffixTestFixture(15, aes.BlockSize-15),
		createSuffixTestFixture(16, aes.BlockSize),
		createSuffixTestFixture(17, aes.BlockSize-1),
	}

	createSuffix := func(length int) []byte {
		res := []byte{}
		for i := 0; i < length; i++ {
			res = append(res, byte(i))
		}
		return res
	}

	for _, f := range fixtures {
		suffix := createSuffix(f.suffixLength)
		encrypter := func(plainText []byte) ([]byte, encryptionMode) {
			return oracleFn(append(plainText, suffix...))
		}

		blockSizeInfo := discoverBlockSizeInfo(encrypter)
		assertEqual(t, f.blockSizeInfo.inputSizeToGetFullPadding, blockSizeInfo.inputSizeToGetFullPadding)
		assertEqual(t, f.blockSizeInfo.blockSize, blockSizeInfo.blockSize)
	}
}

type SuffixTestFixture struct {
	suffixLength  int
	blockSizeInfo BlockSizeInfo
}

func TestAttackTextSize(t *testing.T) {
	// table of knownSize and expected attackTextSize pairs
	tableData := [][]int{
		{0, aes.BlockSize - 1},
		{1, aes.BlockSize - 2},
		{2, aes.BlockSize - 3},
		{3, aes.BlockSize - 4},
		{4, aes.BlockSize - 5},
		{5, aes.BlockSize - 6},
		{6, aes.BlockSize - 7},
		{7, aes.BlockSize - 8},
		{8, aes.BlockSize - 9},
		{9, aes.BlockSize - 10},
		{10, aes.BlockSize - 11},
		{11, aes.BlockSize - 12},
		{12, aes.BlockSize - 13},
		{13, aes.BlockSize - 14},
		{14, aes.BlockSize - 15},
		{15, 0},
		{16, aes.BlockSize - 1},
		{17, aes.BlockSize - 2},
		{18, aes.BlockSize - 3},
		{19, aes.BlockSize - 4},
		{20, aes.BlockSize - 5},
		{21, aes.BlockSize - 6},
		{22, aes.BlockSize - 7},
		{23, aes.BlockSize - 8},
		{24, aes.BlockSize - 9},
		{25, aes.BlockSize - 10},
		{26, aes.BlockSize - 11},
		{27, aes.BlockSize - 12},
		{28, aes.BlockSize - 13},
		{29, aes.BlockSize - 14},
		{30, aes.BlockSize - 15},
		{31, 0},
		{32, aes.BlockSize - 1},
		{33, aes.BlockSize - 2},
	}

	for _, f := range tableData {
		assertEqual(t, f[1], attackTextSize(f[0], aes.BlockSize))
	}
}

func TestChallenge12(t *testing.T) {
	unknown, err := base64.StdEncoding.DecodeString(
		`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)

	if err != nil {
		t.Fatal(err)
	}

	out := Challenge12([]byte(unknown))
	assertEqual(t, string(unknown), out)
}

func TestParseKeyValuePairs(t *testing.T) {
	assertEqual(t, parseKeyValuePairs("foo=bar&baz=qux&zap=zazzle"), Cookies{
		"foo": "bar",
		"baz": "qux",
		"zap": "zazzle",
	})
}

func TestChallenge13(t *testing.T) {
	assertEqual(t, "admin", Challenge13())
}
