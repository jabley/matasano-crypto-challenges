package main

import (
	"bufio"
	"encoding/hex"
	"os"
)

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
		candidate, err := SingleByteXORCipher(scanner.Bytes())
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

func Challenge6() (res string, err error) {
	rawCipher, err := readBase64Input("../inputs/6.txt")

	if err != nil {
		return
	}

	return string(decode(rawCipher)), nil
}

func Challenge7() (res string, err error) {
	rawCipher, err := readBase64Input("../inputs/7.txt")

	if err != nil {
		return
	}

	blockCipher := NewAESECBBlockCipher([]byte("YELLOW SUBMARINE"))
	plainText, err := blockCipher.decrypt(rawCipher)

	if err != nil {
		return
	}

	return string(plainText), nil
}

func Challenge8() (res string, err error) {
	file, err := os.Open("../inputs/8.txt")
	if err != nil {
		return "", err
	}
	defer file.Close()

	// read each line, hex decode the bytes and test it to see if it's ECB-encrypted
	bestScore := -1
	decrypted := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hexBytes := scanner.Bytes()
		cipher, err := decodeHex(hexBytes)

		if err != nil {
			return decrypted, err
		}

		score := scoreECB(cipher)

		if score > bestScore {
			bestScore = score
			decrypted = string(hexBytes)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return decrypted, nil
}
