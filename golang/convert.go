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
