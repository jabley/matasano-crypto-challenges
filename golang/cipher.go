package main

import (
	"crypto/aes"
	"math"
)

func findSingleXORKey(a []byte) (res []byte, score int, key byte) {
	for guess := 0; guess < 256; guess++ {
		out := singleXor(a, byte(guess))
		s := scoreText(out)
		if s > score {
			score = s
			key = byte(guess)
			res = out
		}
	}
	return
}

func findKeySize(rawCipher []byte) int {
	minDistance := math.MaxFloat64
	var keySize int
	n := len(rawCipher)

	for keyLen := 2; keyLen <= 40; keyLen++ {
		blockCount := n/keyLen - 1
		totalDistance := 0.0

		for i := 0; i < blockCount; i++ {
			offset := i * keyLen
			first := rawCipher[offset : offset+keyLen]
			second := rawCipher[offset+keyLen : offset+2*keyLen]
			totalDistance += normalisedDistance(first, second)
		}

		avgDistance := totalDistance / float64(blockCount)

		if minDistance > avgDistance {
			minDistance = avgDistance
			keySize = keyLen
		}
	}

	return keySize
}

func findRepeatingXORKey(in []byte, keySize int) []byte {

	// Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

	// Now transpose the blocks: make a block that is the first byte of every block, and a block
	// that is the second byte of every block, and so on.

	// We have cipher text 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
	// Treat it as:
	// 1234567890abcdef
	// 1234567890abcdef
	// 1234567890abcdef
	// 1234567890abcdef
	// 1234567890abcdef

	// So we make a block containing the each column, and solve single Key XOR for that.

	// Solve each block as if it was single-character XOR. You already have code to do this.

	// For each block, the single-byte XOR key that produces the best looking histogram is the
	// repeating-key XOR key byte for that block. Put them together and you have the key.
	column := make([]byte, (len(in)+keySize-1)/keySize)
	key := make([]byte, keySize)

	for col := 0; col < keySize; col++ {
		for row := range column {
			if row*keySize+col >= len(in) {
				continue
			}
			column[row] = in[row*keySize+col]
		}
		_, _, k := findSingleXORKey(column)
		key[col] = k
	}

	return key

}

func xor(a, b []byte) []byte {
	if len(a) > len(b) {
		a = a[:len(b)]
	}
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res
}

func repeatingXOR(in, key []byte) []byte {
	res := make([]byte, len(in))
	for i, c := range in {
		res[i] = c ^ key[i%len(key)]
	}
	return res
}

func singleXor(in []byte, b byte) []byte {
	res := make([]byte, len(in))
	for i, c := range in {
		res[i] = c ^ b
	}
	return res
}

func detectECB(in []byte) bool {
	if len(in)%aes.BlockSize != 0 {
		panic("detectECB: length not a multiple of blockSize")
	}
	seen := make(map[string]struct{})
	for i := 0; i < len(in); i += aes.BlockSize {
		val := string(in[i : i+aes.BlockSize])
		if _, ok := seen[val]; ok {
			return true
		}
		seen[val] = struct{}{}
	}
	return false
}
