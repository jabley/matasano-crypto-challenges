package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"
)

type encryptionMode int

const (
	MODE_UNKNOWN encryptionMode = iota + 1
	MODE_ECB
	MODE_CBC
)

var encryptionModeName = [...]string{
	MODE_UNKNOWN: "Unknown",
	MODE_ECB:     "ECB",
	MODE_CBC:     "CBC",
}

// EncryptionOracleFn is a function signature for a closure which
// encrypts content consistently. We want to be able to reuse
// oracleEncryption when trying to brute-force it.
type EncryptionOracleFn func([]byte) ([]byte, encryptionMode)

func (m encryptionMode) String() string {
	return encryptionModeName[m]
}

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

	// If the original plainText lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that cipherTexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	return stripPadding(cipherText), nil
}

func encryptECB(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()

	plainText, err = pkcs7(plainText, bs)

	if err != nil {
		return nil, err
	}

	if len(plainText)%bs != 0 {
		return nil, fmt.Errorf("Need a multiple of the blocksize")
	}

	cipherText := make([]byte, 0)

	buf := make([]byte, bs)

	for len(plainText) > 0 {
		block.Encrypt(buf, plainText)
		plainText = plainText[bs:]
		cipherText = append(cipherText, buf...)
	}

	return cipherText, nil
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

func generateEncryptionOracle() EncryptionOracleFn {
	// generate a random key and encrypt under it.
	key := newKey()

	// append 5-10 bytes (count chosen randomly) before the plaintext and
	// 5-10 bytes after the plaintext.
	randomPrefix := newRandomBytes(6)
	randomSuffix := newRandomBytes(6)

	var mode encryptionMode

	// choose to encrypt under ECB 1/2 the time, and under CBC the other half
	if randomInt(2) == 0 {
		mode = MODE_ECB
	} else {
		mode = MODE_CBC
	}

	switch mode {
	case MODE_ECB:
		return newECBEncryptionOracle(key, randomPrefix, randomSuffix)
	case MODE_CBC:
		return newCBCEncryptionOracle(key, randomPrefix, randomSuffix)
	default:
		panic(fmt.Errorf("Unknown mode %q", mode))
	}
}

func NewECBEncryptionOracle() EncryptionOracleFn {
	return newECBEncryptionOracle(newKey(), newRandomBytes(6), newRandomBytes(6))
}

func newECBEncryptionOracle(key, prefix, suffix []byte) EncryptionOracleFn {
	return func(plainText []byte) ([]byte, encryptionMode) {
		plainText = append(append(prefix, plainText...), suffix...)
		cipherText, err := encryptECB(plainText, key)
		if err != nil {
			panic(err)
		}
		return cipherText, MODE_ECB
	}
}

func NewCBCEncryptionOracle() EncryptionOracleFn {
	return newCBCEncryptionOracle(newKey(), newRandomBytes(6), newRandomBytes(6))
}

func newCBCEncryptionOracle(key, prefix, suffix []byte) EncryptionOracleFn {
	return func(plainText []byte) ([]byte, encryptionMode) {
		plainText = append(append(prefix, plainText...), suffix...)
		// just use random IVs each time for CBC
		cipherText, err := encryptCBC(plainText, key, newIv())
		if err != nil {
			panic(err)
		}
		return cipherText, MODE_CBC
	}
}

func sniffEncryptionMode(cipherText []byte) encryptionMode {
	if 0 < scoreECB(cipherText) {
		return MODE_ECB
	}
	return MODE_CBC
}

// newKey generates a new random key of 16 bytes which can be used to encrypt content.
func newKey() []byte {
	res := make([]byte, 16)
	randomBytes(&res)
	return res
}

// newIv generates a new random IV of 16 bytes.
func newIv() []byte {
	return newKey()
}

// newRandomBytes returns a cryptographically random array of up to c bytes.
func newRandomBytes(c int) []byte {
	n := randomInt(c)
	res := make([]byte, n)
	randomBytes(&res)
	return res
}

func randomBytes(dst *[]byte) {
	if _, err := rand.Read(*dst); err != nil {
		panic(err)
	}
}

// randomInt returns, as an int, a non-negative cryptographically strong
// pseudo-random number in [0,n). It panics if n <= 0
func randomInt(n int) int {
	i, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(i.Uint64())
}

// createECBDetectingPlainText returns a byte array with duplication. As
// Challenge 8 taught us, the problem with ECB is that it is stateless
// and deterministic; the same 16 byte plaintext block will always
// produce the same 16 byte ciphertext. So we create 3 blocks of the same
// content so that we can look for a repeating pattern in a encrypted
// output.
func createECBDetectingPlainText(blockSize int) []byte {
	res := make([]byte, blockSize*3)
	plainTextFill(&res)
	return res
}

// plainTextFill sets each entry of the byte array to 'A'. This can be
// useful to having a known, repeating input to a cipher function
func plainTextFill(buf *[]byte) {
	res := *buf
	for i, _ := range res {
		res[i] = 'A'
	}
}
