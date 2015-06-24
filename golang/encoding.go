package main

import (
	"encoding/base64"
	"encoding/hex"
)

func Hex2Base64(hexBytes string) (string, error) {
	data, err := hex.DecodeString(hexBytes)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func decodeHex(hexBytes []byte) ([]byte, error) {
	cipher := make([]byte, hex.DecodedLen(len(hexBytes)))
	_, err := hex.Decode(cipher, hexBytes)

	if err != nil {
		return nil, err
	}

	return cipher, nil
}
