package main

import (
	"encoding/base64"
	"encoding/hex"
)

func hex2Base64(hexBytes string) (string, error) {
	data, err := hex.DecodeString(hexBytes)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}
