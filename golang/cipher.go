package main

import (
	"crypto/aes"
	"encoding/hex"
	"math"
	"reflect"
)

func FixedXOR(first, second string) (string, error) {
	a, err := hex.DecodeString(first)
	if err != nil {
		return "", err
	}
	b, err := hex.DecodeString(second)
	if err != nil {
		return "", err
	}
	var n int
	if len(a) > len(b) {
		n = len(a)
	} else {
		n = len(b)
	}
	dst := make([]byte, n)
	xor(dst, a, b)
	return hex.EncodeToString(dst), nil
}

func SingleByteXORCipher(hexBytes []byte) (string, error) {
	a, err := decodeHex(hexBytes)
	if err != nil {
		return "", err
	}
	return string(decodeAssumingSingleByte(a)), nil
}

func decodeAssumingSingleByte(a []byte) []byte {
	dst := make([]byte, len(a))
	decrypted := make([]byte, len(a))
	bestScore := 0

	for guess := 0; guess < 255; guess++ {
		xor(dst, a, []byte{byte(guess)})

		score := scoreText(dst)

		if score > bestScore {
			// fmt.Printf("Got new best score: %v for %v\n", score, string(dst))
			bestScore = score
			copy(decrypted, dst)
		}
	}

	return decrypted
}

func decode(rawCipher []byte) []byte {
	finalSize := len(rawCipher)
	keysize := guessKeysize(rawCipher)

	// Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

	transposed, blockLength := transpose(rawCipher, keysize)

	// Solve each block as if it was single-character XOR. You already have
	// code to do this.
	// For each block, the single-byte XOR key that produces the best-looking
	// histogram is the repeating-key XOR key byte for that block. Put them
	// together and you have the key.
	decodedTransposition := blockBasedDecoding(transposed, blockLength)
	decoded, _ := transpose(decodedTransposition, blockLength)

	// We need to strip off any bytes added as padding during transpose
	return decoded[:finalSize]
}

func guessKeysize(rawCipher []byte) int {

	minDistance := math.MaxFloat64
	keysize := -1
	n := len(rawCipher)

	for guessedKeysize := 2; guessedKeysize <= 40; guessedKeysize++ {
		blockCount := n/guessedKeysize - 1
		totalDistance := 0.0

		for i := 0; i < blockCount; i++ {
			offset := i * guessedKeysize
			first := rawCipher[offset : offset+guessedKeysize]
			second := rawCipher[offset+guessedKeysize : offset+2*guessedKeysize]
			totalDistance += normalisedDistance(first, second)
		}

		avgDistance := totalDistance / float64(blockCount)

		if minDistance > avgDistance {
			minDistance = avgDistance
			keysize = guessedKeysize
		}
	}

	return keysize
}

// transpose the blocks: make a block that is the first byte of every block,
// and a block that is the second byte of every block, and so on.
// Treat the original contiguous array as an array of blocks (or lines) of
// length blockLength. Transpose this to a contiguous array that we treat as
// an array of blocks or lines of (array.length % blockLength) with suitable
// rounding and padding.
//
// For example, we have an 103 element byte array that we wish to treat as
// having blocks of size 5. We will treat this as 21 blocks of length 5 (need
// some padding on the last one). We will return an array that has 5 blocks
// each of length 21.

func transpose(original []byte, blockLength int) ([]byte, int) {
	newLength := transposeBlockLength(len(original), blockLength)
	n := len(original)
	result := makeTargetBlocks(n, blockLength)

	for i := 0; i < n; i++ {
		line := i / blockLength
		col := i % blockLength
		j := col*newLength + line
		result[j] = original[i]
	}

	return result, newLength
}

func makeTargetBlocks(n int, blockLength int) []byte {
	var padding int
	if n%blockLength == 0 {
		padding = 0
	} else {
		padding = blockLength - n%blockLength
	}
	return make([]byte, n+padding)
}

// transposeBlockLength returns the number of blocks of the specified
// length blockLength required to hold the specified array size n.
func transposeBlockLength(n int, blockLength int) int {
	if n%blockLength == 0 {
		return n / blockLength
	}
	return n/blockLength + 1
}

func blockBasedDecoding(blocks []byte, blockLength int) []byte {
	result := make([]byte, len(blocks))

	for i := 0; i*blockLength < len(blocks); i++ {
		offset := i * blockLength
		decoded := decodeAssumingSingleByte(blocks[offset : offset+blockLength])
		copy(result[offset:offset+blockLength], decoded)
	}

	return result
}

func xor(dst, a []byte, b []byte) {
	n := len(a)
	m := len(b)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i%m]
	}
}

func scoreECB(cipher []byte) int {
	blockLength := len(cipher) / aes.BlockSize
	score := 0

	for i := 0; i < blockLength; i++ {
		offset := i * aes.BlockSize
		block := cipher[offset : offset+aes.BlockSize]
		for j := i + 1; j < blockLength; j++ {
			otherOffset := j * aes.BlockSize
			otherBlock := cipher[otherOffset : otherOffset+aes.BlockSize]
			if reflect.DeepEqual(block, otherBlock) {
				score++
			}
		}
	}

	return score
}
