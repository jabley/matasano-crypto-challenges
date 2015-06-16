package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
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
	dst := make([]byte, len(a))
	decrypted := encrypted
	bestScore := 0

	for guess := 0; guess < 255; guess++ {
		xor(dst, a, []byte{byte(guess)})

		score := scoreText(dst)

		if score > bestScore {
			// fmt.Printf("Got new best score: %v for %v\n", score, string(dst))
			bestScore = score
			decrypted = string(dst)
		}
	}

	return decrypted, nil
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

func xor(dst, a []byte, b []byte) {
	n := len(a)
	m := len(b)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i%m]
	}
}
