package main

import "fmt"

// PKCS#7 is a padding scheme that returns a padded plaintext array that is an even multiple of the blocksize
func pkcs7(original []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 {
		return nil, fmt.Errorf("Invalid parameter: blockSize %d", blockSize)
	}

	nBlocks := len(original) / blockSize

	paddedLength := (nBlocks + 1) * blockSize
	padding := paddedLength - len(original)

	for i := 0; i < padding; i++ {
		original = append(original, byte(padding))
	}

	return original, nil
}

func stripPadding(plainText []byte) []byte {
	n := len(plainText)
	paddingLength := int(plainText[n-1])

	if n-paddingLength < 0 {
		return plainText
	}

	return plainText[:n-paddingLength]
}
