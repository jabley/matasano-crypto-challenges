package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func decryptECB(cipher []byte, key []byte) ([]byte, error) {
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

func decryptCBC(cipherText []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	if len(cipherText)%bs != 0 {
		return nil, fmt.Errorf("Need a multiple of the blocksize")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(cipherText, cipherText)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	return stripPadding(cipherText), nil
}

func encryptCBC(plainText []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()

	// pad plainText to an appropriate size
	paddedPlainText, err := pkcs7(plainText, bs)

	if err != nil {
		return nil, err
	}

	if len(paddedPlainText)%bs != 0 {
		return nil, fmt.Errorf("Need a multiple of the blocksize")
	}

	// encrypt
	cipherText := make([]byte, len(paddedPlainText))
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	// copy(iv[:], cipherText[:bs])

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, paddedPlainText)

	return cipherText, nil
}
