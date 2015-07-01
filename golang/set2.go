package main

import (
	"encoding/base64"
	"io/ioutil"
)

func Challenge9() (string, error) {
	out, err := pkcs7([]byte("YELLOW SUBMARINE"), 20)
	return string(out), err
}

func Challenge10() (res string, err error) {
	rawCipher, err := readBase64Input("../inputs/10.txt")

	if err != nil {
		return
	}

	iv := make([]byte, 16)

	out, err := decryptCBC(rawCipher, []byte("YELLOW SUBMARINE"), iv)
	return string(out), err
}

func Challenge10RoundTrip() (res string, err error) {
	plainText, err := ioutil.ReadFile("../outputs/6.txt")

	if err != nil {
		return
	}

	iv := make([]byte, 16)

	out, err := encryptCBC(plainText, []byte("YELLOW SUBMARINE"), iv)

	return base64.StdEncoding.EncodeToString(out), err
}

func RoundTripECB() (res string, err error) {
	plainText, err := ioutil.ReadFile("../outputs/6.txt")

	if err != nil {
		return
	}

	out, err := encryptECB(plainText, []byte("YELLOW SUBMARINE"))

	return base64.StdEncoding.EncodeToString(out), err
}
