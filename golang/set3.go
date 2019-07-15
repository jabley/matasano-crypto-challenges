package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

func newCBCPaddingOracle(plainText []byte) (
	encrypt func() []byte,
	isValidPadding func([]byte) bool,
) {
	b, _ := aes.NewCipher(newKey())
	iv := newIv()
	blockCipher := newAESCBCBlockCipher(b, iv)

	encrypt = func() []byte {
		in := padPKCS7([]byte(plainText), 16)
		res, err := blockCipher.encrypt(in)
		if err != nil {
			panic(err)
		}
		// See how the attack works, at the start of attackCBCPadding...
		// We need to return the iv as the first block, and the cipher
		// text as the following blocks
		return append(iv, res...)
	}

	isValidPadding = func(in []byte) bool {
		out, err := blockCipher.decrypt(in)
		if err != nil {
			panic(err)
		}
		return isPKCS7Padded(out, 16)
	}

	return
}

func attackCBCPadding(encrypted []byte, isValidPadding func([]byte) bool) []byte {
	// From https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
	// We only need 2 blocks:
	// * the second block will contain the PKCS7 padding
	// * the first block will act like the initialisation vector in CBC decryption

	// for the 2nd block, we might have plain text of:
	//
	// 1. XXXXXXXXXXX55555
	// 2. XXXXXXXXXXXXXXX1
	// 3. XXXXXXXXXXXXXX21
	// 4. XXXXXXXXXXXXXXXX
	//
	// If we twiddle the cipher text blocks and manage to set the last byte to
	// 1 when it's been decrypted, then that will be valid PKCS7 padding.
	//
	// Applying this to our test cases above:
	//
	// 1. will seem to have valid padding when we've set the last byte to 1 or 5
	// 2. will have valid padding when we've set the last byte to 1 or maybe 2 if the last plain text byte is 0x02)
	// 3. will have valid padding when we've set the last byte to 1 or 2
	// 4. will have valid padding when we've set the last byte to 1 (or maybe 2 if the last plain text byte is 0x02)
	//
	// So there are some edge cases that we'll need to detect as part of our implementation
	findNextByte := func(known, iv, block []byte) []byte {
		if len(block) != 16 || len(iv) != 16 || len(known) >= 16 {
			panic("wrong lengths for findNextByte")
		}

		buf := make([]byte, 32)
		copy(buf[16:], block)
		plaintext := append([]byte{0x00}, known...)
		padding := byte(len(plaintext))

		for i := 0; i < 256; i++ {
			copy(buf, iv)
			plaintext[0] = byte(i)

			for i := range plaintext {
				// erase the known bytes by flipping them
				buf[len(buf)-1-16-i] ^= plaintext[len(plaintext)-1-i]
				// apply valid padding for the current byte we're attacking
				buf[len(buf)-1-16-i] ^= padding
			}

			// check we actually changed something. If we've produced
			// the same as the `iv`` after all our bit-twiddling, we
			// already know that's valid because it's what our
			// (hopefully correct!) encryption function produced.
			if bytes.Equal(buf[:16], iv) {
				continue
			}

			if isValidPadding(buf) {
				return plaintext
			}
		}

		// if the only one that works is not changing anything, there's
		// already a padding of `padding`. This is the edge cases
		// described in 2. and 4. above.
		plaintext[0] = padding
		for _, c := range plaintext {
			if c != padding {
				plaintext[1] ^= padding
				return plaintext[1:] // correct and retry
			}
		}

		return plaintext
	}

	if len(encrypted)%16 != 0 {
		panic("unexpected cipher text length")
	}

	nBlocks := len(encrypted) / 16
	var plainText []byte
	for i := nBlocks; i > 1; i-- {
		var known []byte
		start := (i - 1) * 16
		iv := encrypted[start-16 : start]
		block := encrypted[start : start+16]

		for len(known) < 16 {
			known = findNextByte(known, iv, block)
		}

		plainText = append(known, plainText...)
	}

	return plainText
}

func decryptCTR(b cipher.Block, ct, nonce []byte) []byte {
	var out []byte

	if len(nonce) >= b.BlockSize() {
		panic("nonce cannot be larger than the block size")
	}

	src, dst := make([]byte, b.BlockSize()), make([]byte, b.BlockSize())
	copy(src, nonce)

	for i := 0; i < len(ct); i += b.BlockSize() {
		b.Encrypt(dst, src)
		out = append(out, xor(dst, ct[i:])...)

		// Increment the 64 bit little endian block count
		binary.LittleEndian.PutUint64(src[8:], binary.LittleEndian.Uint64(src[8:])+1)
	}

	return out
}

var encryptCtr = decryptCTR

func findFixedNonceKeyBySubstitution(plaintexts, ciphertext [][]byte) []byte {
	res := make([]byte, 0)

	for i := 0; i < 16; i++ {
		bestScore, byteScore := 0, 0
		var bestGuess byte

		for guess := 0; guess < 256; guess++ {
			byteScore = 0

			for _, ct := range ciphertext {
				plain := ct[i] ^ byte(guess)
				if isEnglishCharacter(plain) {
					byteScore++
				}
			}

			if byteScore > bestScore {
				bestScore = byteScore
				bestGuess = byte(guess)
			}
		}

		res = append(res, bestGuess)
	}
	// for i, text := range plaintexts {
	// 	res = make([]byte, 0)
	// 	for j := 0; j < 16; j++ {
	// 		guess := text[j] ^ ciphertext[i][j]
	// 		res = append(res, guess)
	// 	}

	// 	println(fmt.Sprintf("From plain text %d, guess is %v", i, res))

	// 	res = make([]byte, 0)
	// 	for j := 16; j < 32; j++ {
	// 		guess := text[j] ^ ciphertext[i][j]
	// 		res = append(res, guess)
	// 	}

	// 	println(fmt.Sprintf("From plain text %d, guess is %v", i, res))
	// }

	println(fmt.Sprintf("guess is %v", res))

	return res
}
