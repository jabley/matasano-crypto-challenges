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

func isPkcs7Padded(buf []byte, bs int) bool {
	n := len(buf)
	if n == 0 {
		return false
	}

	// Read the last byte
	padding := buf[n-1]

	// Check that it's an int below block size
	if !(int(padding) > 0 && int(padding) < bs) {
		return false
	}

	for _, b := range buf[n-int(padding):] {
		if b != padding {
			return false
		}
	}

	return true
}

func stripPadding(plainText []byte) []byte {
	n := len(plainText)
	paddingLength := int(plainText[n-1])

	if n-paddingLength < 0 {
		return plainText
	}

	return plainText[:n-paddingLength]
}

type BlockSizeInfo struct {
	inputSizeToGetFullPadding int // the size of input required to get blockSize-1 padding bytes
	blockSize                 int // the block size for the block cipher
}

func (bs *BlockSizeInfo) String() string {
	return fmt.Sprintf("[BlockSizeInfo inputSizeToGetFullPadding=%d blockSize=%d]", bs.inputSizeToGetFullPadding, bs.blockSize)
}

// discoverBlockSizeInfo assumes that the encrypter function is using a block
// cipher. You can determine the block size by incrementing the input one
// byte at a time, and observing when the cipher text size jumps by multiple
// bytes; ie the block size.
func discoverBlockSizeInfo(encrypter EncryptionOracleFn) BlockSizeInfo {
	// Assume block size is 8:
	// =>
	// suffix | inputSizeToGetFullPadding
	//    0   |           8
	//    1   |           7
	//    2   |           6
	//    3   |           5
	//    4   |           4
	//    5   |           3
	//    6   |           2
	//    7   |           1
	//    8   |           8
	//    9   |           7

	plainText := []byte{}
	cipher, _ := encrypter(plainText)
	initialLength := len(cipher)
	cipherLength := initialLength

	for cipherLength == initialLength {
		plainText = append(plainText, 'A')
		cipher, _ = encrypter(plainText)
		cipherLength = len(cipher)
	}

	bs := cipherLength - initialLength
	return BlockSizeInfo{
		inputSizeToGetFullPadding: len(plainText),
		blockSize:                 bs,
	}
}
