package main

import (
	"crypto/aes"
	"fmt"
)

func decryptEBC(cipher []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	if len(cipher)%bs != 0 {
		return nil, fmt.Errorf("Need a multiple of the blocksize")
	}

	plainText := make([]byte, 0)
	buf := make([]byte, bs)

	for len(cipher) > 0 {
		block.Decrypt(buf, cipher)
		cipher = cipher[bs:]
		plainText = append(plainText, buf...)
	}

	return stripPadding(plainText), nil
}
