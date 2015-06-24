package main

import (
	"encoding/base64"
	"io/ioutil"
)

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
