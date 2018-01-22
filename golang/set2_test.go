package main

import (
	"crypto/aes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestChallenge9(t *testing.T) {
	out := padPKCS7([]byte("YELLOW SUBMARINE"), 20)
	assertEqual(t, []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), out)
}

func TestChallenge10(t *testing.T) {
	cipherText := decodeBase64(t, string(readFile(t, "../inputs/10.txt")))

	iv := make([]byte, 16)
	b, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	fatalIfErr(t, err)
	blockCipher := newAESCBCBlockCipher(b, iv)

	out, err := blockCipher.decrypt(cipherText)
	fatalIfErr(t, err)
	plainText := readFile(t, "../outputs/6.txt")
	assertEqual(t, plainText, unpadPKCS7(out))

	// Try going the other way
	b64CipherText := string(readFile(t, "../inputs/10.txt"))
	out, err = blockCipher.encrypt(padPKCS7(plainText, 16))
	fatalIfErr(t, err)
	assertEqual(t, strings.Replace(string(b64CipherText), "\n", "", -1), encodeBase64(out))
}

func TestRoundTripECB(t *testing.T) {
	plainText := readFile(t, "../outputs/6.txt")

	b, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	fatalIfErr(t, err)
	blockCipher := newAESECBBlockCipher(b)
	out, err := blockCipher.encrypt(padPKCS7(plainText, 16))
	fatalIfErr(t, err)
	expected := readFile(t, "../inputs/7.txt")

	// the base64 encoded version we generate has no \n formatting, so we trim that from the file read
	// (which does contain \n for readability)
	expectedStr := strings.Replace(string(expected), "\n", "", -1)
	assertEqual(t, expectedStr, encodeBase64(out))
}

func TestChallenge11(t *testing.T) {
	plainText := createECBDetectingPlainText(aes.BlockSize)

	// run it a few times to try to cover both CBC and ECB
	for i := 0; i < 20; i++ {
		oracle := newOracle()
		cipherText, mode := oracle(plainText)
		detectedMode := sniffEncryptionMode(cipherText)
		assertEqual(t, mode, detectedMode)
	}
}

func TestBlockSizeInfoForDifferentSuffixLengths(t *testing.T) {
	oracleFn := newECBSuffixOracle([]byte{})

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
	unknown := decodeBase64(t,
		`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)

	oracle := newECBSuffixOracle(unknown)

	blockSizeInfo := discoverBlockSizeInfo(oracle)

	cipherText := askOracle(oracle, createECBDetectingPlainText(blockSizeInfo.blockSize))

	if sniffEncryptionMode(cipherText) != MODE_ECB {
		t.Error("oracle isn't using ECB")
	}

	out := string(discoverSuffix(blockSizeInfo, oracle))
	assertEqual(t, string(unknown), out)
}

func TestParseKeyValuePairs(t *testing.T) {
	assertEqual(t, parseKeyValuePairs("foo=bar&baz=qux&zap=zazzle"), Cookies{
		"foo": "bar",
		"baz": "qux",
		"zap": "zazzle",
	})
	assertEqual(t, parseKeyValuePairs("email=foo@bar.com&role=admin&role=user"), Cookies{
		"email": "foo@bar.com",
		"role":  "admin",
	})
}

func TestChallenge13(t *testing.T) {
	b, err := aes.NewCipher(newKey())
	fatalIfErr(t, err)
	blockCipher := newAESECBBlockCipher(b)
	encryptUserProfile := func(email string) []byte {
		profile := ProfileFor(email)
		msg := padPKCS7([]byte(profile), 16)
		cipherText, err := blockCipher.encrypt(msg)
		if err != nil {
			panic(err)
		}
		return cipherText
	}

	decryptAndGetRole := func(cipherText []byte) string {
		plainText, err := blockCipher.decrypt(cipherText)
		if err != nil {
			panic(err)
		}
		return parseKeyValuePairs(string(plainText))["role"]
	}

	out := elevateToAdmin(encryptUserProfile, decryptAndGetRole)

	assertEqual(t, "admin", out)
}

func encodeBase64(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}

func TestChallenge14(t *testing.T) {
	unknown, err := base64.StdEncoding.DecodeString(
		`Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`)

	if err != nil {
		t.Fatal(err)
	}

	oracle := newECBSuffixOracleWithPrefix(unknown)
	blockSizeInfo := discoverBlockSizeInfo(oracle)
	cipherText := askOracle(oracle, createECBDetectingPlainText(blockSizeInfo.blockSize))

	if sniffEncryptionMode(cipherText) != MODE_ECB {
		panic("encrypter isn't using ECB")
	}

	// we have ES-128-ECB(random-prefix || your-string || unknown-string, random-key)
	out := string(discoverSuffixWithRandomPrefix(blockSizeInfo, oracle))

	assertEqual(t, string(unknown), out)
}

func TestChallenge15(t *testing.T) {
	assertEqual(t, true, isPKCS7Padded([]byte("ICE ICE BABY\x04\x04\x04\x04"), 16))
	assertEqual(t, "ICE ICE BABY", string(unpadPKCS7([]byte("ICE ICE BABY\x04\x04\x04\x04"))))
	assertEqual(t, false, isPKCS7Padded([]byte("ICE ICE BABY\x05\x05\x05\x05"), 16))
	assertEqual(t, false, isPKCS7Padded([]byte("ICE ICE BABY\x01\x02\x03\x04"), 16))
}

func TestChallenge16(t *testing.T) {
	generateCookie, amIAdmin := newCBCCookieOracles()

	// generateCookie escapes ; and = characters, this attack would be too easy
	assertEqual(t, false, amIAdmin(generateCookie(";role=admin;")))
	assertEqual(t, true, amIAdmin(makeCBCAdminCookie(generateCookie)))
}
