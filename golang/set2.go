package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"strings"
)

func discoverSuffix(blockSizeInfo BlockSizeInfo, oracle EncryptionOracleFn) []byte {
	// Knowing the block size, craft an input block that is exactly 1 byte
	// short (for instance, if the block size is 8 bytes, make "AAAAAAA").
	// Think about what the oracle function is going to put in that last
	// byte position.

	// We have:
	//
	// AES-128-ECB(your-string || unknown-string, random-key)
	//
	// So we know how long to make your-string so that the first byte of
	// unknown-string is included as part of the first block. We can then do an
	// attack which tries all byte values to see what the first byte of
	// unknown-string is. Repeat with different padding to see what the second
	// byte is, etc.

	// for example, with a block size of 8:
	// content:	|your-string   |  suffix | [padding]|
	// bytes:		| A A A A A A A ? | ? ? ? 5 5 5 5 5 |
	// pos:			| 1 2 3 4 5 6 7 8 | 1 2 3 4 5 6 7 8 |
	//
	// here inputSizeToGetFullPadding would be 7, block size is 8, and input
	// should be 12 so that the first byte of suffix is the last byte of the
	// second block for the input

	bs := blockSizeInfo.blockSize

	known := []byte{}

	for {
		attackSize := attackTextSize(len(known), bs)

		attackText := bytes.Repeat([]byte{'A'}, attackSize)

		missingLastByteCipherText := askOracle(oracle, attackText)

		start := bs * (len(known) / bs)
		end := start + bs

		interestingBlock := missingLastByteCipherText[start:end]

		// Make a dictionary of every possible last byte by feeding different
		// strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
		// "AAAAAAAC", remembering the first block of each invocation.
		table := makeDict(oracle, bs, known)

		// Match the output of the one-byte-short input to one of the entries in
		// your dictionary. You've now discovered the first byte of
		// `unknown-string`.
		if _, ok := table[hashKeyFromBytes(interestingBlock)]; ok {
			known = append(known, table[hashKeyFromBytes(interestingBlock)])
		} else {
			panic(fmt.Sprintf("failed to find result"))
		}

		// if the output is pkcs7 padded then we are done
		if isPKCS7Padded(known, bs) {
			known = unpadPKCS7(known)
			break
		}

		// Repeat for the next byte
	}

	return known
}

func discoverSuffixWithRandomPrefix(blockSizeInfo BlockSizeInfo, oracle EncryptionOracleFn) []byte {
	// AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
	//
	// The input `random-prefix || attacker-controlled || target-bytes` will be
	// padded to a multiple of block size.

	bs := blockSizeInfo.blockSize

	prefixSize := discoverPrefixSize(bs, oracle)

	// We know how long the prefix is. So we know how long to make attacker-controlled so
	// that the first byte of target-bytes is part of a block
	return discoverSuffix(blockSizeInfo, func(in []byte) ([]byte, encryptionMode) {
		p := bs - prefixSize%bs
		msg := append(bytes.Repeat([]byte{'A'}, p), in...)
		out := askOracle(oracle, msg)
		return out[prefixSize+p:], MODE_ECB
	})
}

// discoverPrefixSize tries to determine how long the prefix is in the EncryptionOracleFn.
// returns the prefix size in bytes
func discoverPrefixSize(bs int, oracle EncryptionOracleFn) int {
	// We can find out how long the random prefix is by:
	// - create an n block long attack text
	attackText := createECBDetectingPlainText(bs)

	// - search for a n block long cipher text out
	for i := 0; i < bs; i++ {
		padding := make([]byte, i)
		plainText := append(padding, attackText...)

		// - keep prepending a padding byte until we find a n block long cipher text
		cipherText := askOracle(oracle, plainText)

		blockText, location := findRepeatingBlock(cipherText, bs, len(attackText)/bs)

		if location != -1 {
			// - change the attack text content (but not the prefix padding) and confirm that
			//   we get a different n block long cipher text AT THE SAME LOCATION
			attackText = bytes.Repeat([]byte{'B'}, len(attackText))
			plainText := append(padding, attackText...)
			cipherText := askOracle(oracle, plainText)
			newBlock, newLocation := findRepeatingBlock(cipherText, bs, len(attackText)/bs)
			if newLocation == location && !bytes.Equal(blockText, newBlock) {
				// profit!
				return location*bs - i
			}
		}

		// - repeat until we know the prefix size
	}

	panic("Could not determine the prefix size")
}

// findRepeatingBlock returns the first repeating block of count blocks
// of blockSize, or -1 if there isn't one.
// For example, with a blockSize of 16, find 3 repeating blocks.
func findRepeatingBlock(buf []byte, blockSize int, count int) (content []byte, location int) {
	if len(buf)%blockSize != 0 {
		panic("Need multiple of block size")
	}

	location = -1

	totalBlocks := len(buf) / blockSize

	var previous []byte
	seen := 0

	for i := 0; i < totalBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		chunk := buf[start:end]

		if bytes.Equal(previous, chunk) {
			seen++
			if seen == count {
				content = chunk
				location = i + 1 - seen
				break
			}
		} else {
			seen = 1
		}
		previous = chunk
	}

	return
}

// attackTextSize returns the size of attack text padding needed to discover the next byte.
func attackTextSize(knownSize, blockSize int) int {
	return blockSize - 1 - (knownSize % blockSize)
}

// makeDict returns a map of byte values keyed by hash key of a cipher block.
func makeDict(oracle EncryptionOracleFn, blockSize int, known []byte) map[string]byte {
	res := make(map[string]byte)

	msg := bytes.Repeat([]byte{'A'}, blockSize)
	msg = append(msg, known...)
	msg = append(msg, '?')
	msg = msg[len(msg)-blockSize:]

	for guess := 0; guess < 256; guess++ {
		b := byte(guess)
		msg[blockSize-1] = b
		cipherText := askOracle(oracle, msg)[:blockSize]
		res[hashKeyFromBytes(cipherText)] = b
	}

	return res
}

func askOracle(oracle EncryptionOracleFn, msg []byte) []byte {
	out, _ := oracle(msg)
	return out
}

// hashKeyFromBytes is used since golang can't use a slice as a key for a map, since equality isn't defined.
func hashKeyFromBytes(buf []byte) string {
	return string(buf)
}

func elevateToAdmin(encryptUserProfile func(string) []byte, decryptAndGetRole func([]byte) string) string {
	start := "email="

	genBlock := func(prefix string) string {
		msg := strings.Repeat("A", 16-len(start)) + prefix
		return string(encryptUserProfile(msg))[16:32]
	}

	emailBlock := string(encryptUserProfile("me@foo.bar"))[:16]                       // email=me@foo.bar
	padEmailBlock := genBlock(strings.Repeat("A", 16-len("&uid=10&role=")))           // AAA&uid=10&role=
	adminBlock := genBlock("admin")                                                   // admin&uid=10&rol
	trailingBlock := string(encryptUserProfile(strings.Repeat("A", 16-len(start)-1))) // email=AAAAAAAAA&uid=10&role=user

	elevatedProfile := emailBlock + padEmailBlock + adminBlock + trailingBlock

	return decryptAndGetRole([]byte(elevatedProfile))
}

func newCBCCookieOracles() (
	generateCookie func(string) string,
	amIAdmin func(string) bool,
) {
	// Generate a random AES key.
	b, _ := aes.NewCipher(newKey())
	iv := newIv()
	blockCipher := newAESCBCBlockCipher(b, iv)

	generateCookie = func(userdata string) string {
		// The function should quote out the ";" and "=" characters.
		userdata = strings.Replace(userdata, ";", "%3B", -1)
		userdata = strings.Replace(userdata, "=", "%3D", -1)

		// The first function should take an arbitrary input string, prepend the string:
		//
		// "comment1=cooking%20MCs;userdata="
		//
		// and append the string:
		//
		// ";comment2=%20like%20a%20pound%20of%20bacon"
		msg := "comment1=cooking%20MCs;userdata=" + userdata + ";comment2=%20like%20a%20pound%20of%20bacon"

		// The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.
		out, _ := blockCipher.encrypt(padPKCS7([]byte(msg), 16))
		return string(out)
	}

	amIAdmin = func(in string) bool {
		// The second function should decrypt the string
		msg := []byte(in)
		out, _ := blockCipher.decrypt(msg)
		// and look for the characters ";role=admin;"
		return bytes.Contains(out, []byte(";role=admin;"))
	}

	return
}

func xorString(a, b string) string {
	return string(xor([]byte(a), []byte(b)))
}

func makeCBCAdminCookie(generateCookie func(string) string) string {
	prefix := "comment1=cooking%20MCs;userdata="

	// justify "0123456789ABCDEF"
	desired := "AA;role=admin;AA"
	userDataBuf := strings.Repeat("?", 16*2)

	out := generateCookie(userDataBuf)

	leadingSlice := out[:len(prefix)]
	targetBlock := out[len(prefix) : len(prefix)+16]
	trailingSlice := out[len(prefix)+16:]

	// Insert our attack text into the block
	targetBlock = xorString(targetBlock, xorString(strings.Repeat("?", 16), desired))

	return leadingSlice + targetBlock + trailingSlice
}
