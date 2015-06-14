package main

import (
	"encoding/base64"
	"encoding/hex"
	"math"
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
	dst := make([]byte, int(math.Max(float64(len(a)), float64(len(b)))))
	XORBytes(dst, a, b)
	return hex.EncodeToString(dst), nil
}

func XORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
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
		xor(dst, a, byte(guess))

		score := scoreText(dst)

		if score > bestScore {
			// fmt.Printf("Got new best score: %v for %v\n", score, string(dst))
			bestScore = score
			decrypted = string(dst)
		}
	}

	return decrypted, nil
}

func xor(dst, a []byte, b byte) {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b
	}
}
