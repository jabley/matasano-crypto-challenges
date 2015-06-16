package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"math"
	"os"
)

func Hex2Base64(hexBytes string) (string, error) {
	data, err := hex.DecodeString(hexBytes)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

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

func SingleByteXORCipher(encrypted string) (string, error) {
	a, err := hex.DecodeString(encrypted)
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

func Challenge4() (string, error) {
	file, err := os.Open("../inputs/4.txt") // For read access.
	if err != nil {
		return "", err
	}
	defer file.Close()

	bestScore := 0
	decrypted := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		candidate, err := SingleByteXORCipher(scanner.Text())
		if err != nil {
			return "", err
		}

		score := scoreText([]byte(candidate))

		if score > bestScore {
			bestScore = score
			decrypted = candidate
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return decrypted, nil
}

func Challenge5() (string, error) {
	in := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	a := []byte(in)
	dst := make([]byte, len(a))
	b := []byte{'I', 'C', 'E'}
	xor(dst, a, b)
	return hex.EncodeToString(dst), nil
}

func HammingDistance(a, b string) int {
	return editDistance([]byte(a), []byte(b))
}

func editDistance(a, b []byte) int {
	dist := 0
	for i := range a {
		val := a[i] ^ b[i]
		for val != 0 {
			dist++
			val &= val - 1
		}
	}
	return dist
}

func normalisedDistance(a, b []byte) float64 {
	return float64(editDistance(a, b)) / float64(len(a))
}

func Challenge6() (res string, err error) {
	rawCipher, err := readBase64Input("../inputs/6.txt")

	if err != nil {
		return
	}

	return string(decode(rawCipher)), nil
}

func readBase64Input(path string) ([]byte, error) {
	src, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	rawCipher, err := base64.StdEncoding.DecodeString(string(src))

	if err != nil {
		return nil, err
	}

	return rawCipher, nil
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
