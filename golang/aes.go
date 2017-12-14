package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"time"
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

type BlockCipher interface {
	decrypt(cipher []byte) ([]byte, error)
	encrypt(plain []byte) ([]byte, error)
}

type AESECBBlockCipher struct {
	block cipher.Block
}

func newAESECBBlockCipher(b cipher.Block) BlockCipher {
	return &AESECBBlockCipher{
		block: b,
	}
}

func (c *AESECBBlockCipher) decrypt(cipher []byte) ([]byte, error) {
	bs := c.block.BlockSize()
	if len(cipher)%bs != 0 {
		return nil, fmt.Errorf("Need a multiple of the blocksize")
	}

	plainText := make([]byte, len(cipher))
	for i := 0; i < len(cipher); i += bs {
		c.block.Decrypt(plainText[i:], cipher[i:])
	}

	return unpadPKCS7(plainText), nil
}

func (c *AESECBBlockCipher) encrypt(plainText []byte) ([]byte, error) {
	bs := c.block.BlockSize()

	if len(plainText)%bs != 0 {
		return nil, fmt.Errorf("Need a multiple of the blocksize")
	}

	cipherText := make([]byte, len(plainText))

	for i := 0; i < len(plainText); i += bs {
		c.block.Encrypt(cipherText[i:], plainText[i:])
	}

	return cipherText, nil
}

type AESCBCBlockCipher struct {
	block cipher.Block
	iv    []byte
}

func newAESCBCBlockCipher(b cipher.Block, iv []byte) BlockCipher {
	return &AESCBCBlockCipher{
		block: b,
		iv:    iv,
	}
}

func (c *AESCBCBlockCipher) decrypt(cipherText []byte) ([]byte, error) {
	bs := c.block.BlockSize()
	if len(cipherText)%bs != 0 {
		return nil, fmt.Errorf("Need a multiple of the blocksize")
	}

	// decrypt – don't use OpenSSL (or indeed Go cipher.BlockMode implementations)
	// because you don't learn anything

	plainText := make([]byte, len(cipherText))
	prev := c.iv
	buf := make([]byte, bs)
	for i := 0; i < len(cipherText)/bs; i++ {
		c.block.Decrypt(buf, cipherText[i*bs:])
		copy(plainText[i*bs:], xor(buf, prev))
		prev = cipherText[i*bs : (i+1)*bs]
	}

	// If the original plainText lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that cipherTexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	return unpadPKCS7(plainText), nil
}

func (c *AESCBCBlockCipher) encrypt(plainText []byte) ([]byte, error) {
	bs := c.block.BlockSize()

	if len(plainText)%bs != 0 {
		return nil, fmt.Errorf("Need a multiple of the blocksize")
	}

	// encrypt – don't use OpenSSL (or indeed Go cipher.BlockMode implementations)
	// because you don't learn anything
	out := make([]byte, len(plainText))
	prev := c.iv
	for i := 0; i < len(plainText)/bs; i++ {
		copy(out[i*bs:], xor(plainText[i*bs:(i+1)*bs], prev))
		c.block.Encrypt(out[i*bs:], out[i*bs:])
		prev = out[i*bs : (i+1)*bs]
	}
	return out, nil
}

func newOracle() EncryptionOracleFn {
	// generate a random key and encrypt under it.
	b, _ := aes.NewCipher(newKey())

	var mode encryptionMode
	var blockCipher BlockCipher
	// choose to encrypt under ECB 1/2 the time, and under CBC the other half
	if mathrand.Intn(2) == 0 {
		mode = MODE_ECB
		blockCipher = newAESECBBlockCipher(b)
	} else {
		mode = MODE_CBC
		// just use random IVs each time for CBC
		blockCipher = newAESCBCBlockCipher(b, newIv())
	}

	return func(plainText []byte) ([]byte, encryptionMode) {
		// append 5-10 bytes (count chosen randomly) before the plaintext and
		// 5-10 bytes after the plaintext.
		randomPrefix := newRandomBytes(6)
		randomSuffix := newRandomBytes(6)

		plainText = append(append(randomPrefix, plainText...), randomSuffix...)
		cipherText, err := blockCipher.encrypt(padPKCS7(plainText, 16))
		if err != nil {
			panic(err)
		}
		return cipherText, mode
	}
}

func newECBSuffixOracle(secret []byte) EncryptionOracleFn {
	b, _ := aes.NewCipher(newKey())
	blockCipher := newAESECBBlockCipher(b)

	return func(in []byte) ([]byte, encryptionMode) {
		msg := padPKCS7(append(in, secret...), 16)
		out, err := blockCipher.encrypt(msg)
		if err != nil {
			panic(err)
		}
		return out, MODE_ECB
	}
}

func init() {
	mathrand.Seed(time.Now().Unix())
}

func newECBSuffixOracleWithPrefix(secret []byte) EncryptionOracleFn {
	b, _ := aes.NewCipher(newKey())
	blockCipher := newAESECBBlockCipher(b)

	prefix := make([]byte, mathrand.Intn(100))

	return func(in []byte) ([]byte, encryptionMode) {
		rand.Read(prefix)
		msg := padPKCS7(append(prefix, append(in, secret...)...), 16)
		out, err := blockCipher.encrypt(msg)
		if err != nil {
			panic(err)
		}
		return out, MODE_ECB
	}
}

func sniffEncryptionMode(cipherText []byte) encryptionMode {
	if detectECB(cipherText) {
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

// randomBytes fills the dst byte array with a cryptographically secure sequence of bytes.
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
// content so that we can look for a repeating pattern of 2 blocks in a
// encrypted output. 3 blocks input means we get at least 2 blocks
// duplicate output, even if there is some random prefix and our input
// isn't aligned on block boundaries.
func createECBDetectingPlainText(blockSize int) []byte {
	return bytes.Repeat([]byte{'A'}, blockSize*3)
}
