package main

import (
	"bytes"
	"fmt"
)

func discoverSuffix(blockSizeInfo BlockSizeInfo, oracle EncryptionOracleFn) []byte {
	// Knowing the block size, craft an input block that is exactly 1 byte
	// short (for instance, if the block size is 8 bytes, make "AAAAAAA").
	// Think about what the oracle function is going to put in that last
	// byte position.

	// We have:
	//
	// AES-128-ECB(your-string || unknown-string, random-key)
	//
	// So we know how long to make your-string so that the first byte of
	// unknown-string is included as part of the first block. We can then do an
	// attack which tries all byte values to see what the first byte of
	// unknown-string is. Repeat with different padding to see what the second
	// byte is, etc.

	// for example, with a block size of 8:
	// content:	|your-string   |  suffix | [padding]|
	// bytes:		| A A A A A A A ? | ? ? ? 5 5 5 5 5 |
	// pos:			| 1 2 3 4 5 6 7 8 | 1 2 3 4 5 6 7 8 |
	//
	// here inputSizeToGetFullPadding would be 7, block size is 8, and input
	// should be 12 so that the first byte of suffix is the last byte of the
	// second block for the input

	bs := blockSizeInfo.blockSize

	known := []byte{}

	for {
		attackSize := attackTextSize(len(known), bs)

		attackText := bytes.Repeat([]byte{'A'}, attackSize)

		missingLastByteCipherText, _ := oracle(attackText)

		start := bs * (len(known) / bs)
		end := start + bs

		interestingBlock := missingLastByteCipherText[start:end]

		// Make a dictionary of every possible last byte by feeding different
		// strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
		// "AAAAAAAC", remembering the first block of each invocation.
		prefix := append(attackText, known...)
		trailingBlockStart := (len(prefix) / bs) * bs
		table := buildLookupTable(oracle, bs, prefix[trailingBlockStart:])

		// Match the output of the one-byte-short input to one of the entries in
		// your dictionary. You've now discovered the first byte of
		// `unknown-string`.
		if _, ok := table[hashKeyFromBytes(interestingBlock)]; ok {
			known = append(known, table[hashKeyFromBytes(interestingBlock)])
		} else {
			panic(fmt.Sprintf("failed to find result"))
		}

		// if the output is pkcs7 padded then we are done
		if isPKCS7Padded(known, bs) {
			known = unpadPKCS7(known)
			break
		} else {
			// Repeat for the next byte
		}
	}

	return known
}

// attackTextSize returns the size of attack text padding needed to discover the next byte.
func attackTextSize(knownSize, blockSize int) int {
	return blockSize - 1 - (knownSize % blockSize)
}

// findLongestRepeat returns the number of instances of the longest repeating
// block, and which block is the first.
func findLongestRepeat(buf []byte, blockSize int) (max int, content []byte, location int) {
	if len(buf)%blockSize != 0 {
		panic("Need multiple of block size")
	}

	totalBlocks := len(buf) / blockSize

	var previous []byte
	count := 1

	for i := 0; i < totalBlocks; i++ {
		start := i * blockSize
		end := start + blockSize
		chunk := buf[start:end]

		if bytes.Equal(previous, chunk) {
			count++
			if count > max {
				max = count
				content = chunk
				location = i - max
			}
		} else {
			count = 1
		}
		previous = chunk
	}

	return
}

// buildLookupTable returns a map of byte values keyed by hash key of a cipher block.
func buildLookupTable(oracle EncryptionOracleFn, blockSize int, prefix []byte) map[string]byte {
	if len(prefix) != blockSize-1 {
		panic(fmt.Sprintf("expected one shorter than block size %d but was %d", blockSize, len(prefix)))
	}

	res := make(map[string]byte)

	for guess := 0; guess < 256; guess++ {
		b := byte(guess)
		plainText := append(prefix, b)
		cipherText := blockOracle(oracle, blockSize, plainText)
		res[hashKeyFromBytes(cipherText)] = b
	}

	return res
}

func blockOracle(oracle EncryptionOracleFn, blockSize int, prefix []byte) []byte {
	if len(prefix) != blockSize {
		panic("Expected block size bytes")
	}

	repeats := 2
	repeatedText := bytes.Repeat(prefix, repeats)
	buf := make([][]byte, blockSize)
	for i := range buf {
		buf[i] = repeatedText
	}

	input := bytes.Join(buf, []byte{byte(0)})

	cipherText, _ := oracle(input)

	max, content, _ := findLongestRepeat(cipherText, blockSize)

	if max == repeats {
		return content
	}

	panic(fmt.Sprintf("Failed to find encrypted bytes, Found %d\n", max))
}

// hashKeyFromBytes is used since golang can't use a slice as a key for a map, since equality isn't defined.
func hashKeyFromBytes(buf []byte) string {
	return string(buf)
}

func elevateToAdmin(encryptUserProfile func(string) []byte, decryptAndGetRole func([]byte) string) string {
	// Create an encrypted thing that we can take a block off
	// So encryptUserProfile will create a structure with email=the-email&uid=10&role=user
	// We can attack that by considering where the block boundaries are.
	//
	// 0123456789abcdef0123456789abcdef0123456789abcdef - position
	// email=AAAAAAAAAAadmin&uid=10&role=10pppppppppppp - attack text
	//
	// (where p is pkcs7 padding)
	// Slicing the 2nd block will give us the encrypted text for admin

	adminBlock := encryptUserProfile("AAAAAAAAAAadmin")[16:32]

	// Doing another attack of:
	// 0123456789abcdef0123456789abcdef0123456789abcdef - position
	// email=u@trustme.com&uid=10&role=userpppppppppppp - attack text
	//
	// Slicing the first 2 blocks will give the encrypted text for
	// email=u@trustme.com&uid=10&role=
	// Taking the remaining trailing blocks will give us the correctly
	// padded ending which can be decrypted.
	// Putting the single block from the first attack in the middle gives:
	//
	// email=u@trustme.com&uid=10&role=admin&uid=10&roluser

	toCut := encryptUserProfile("u@trustme.com")
	encryptedEmailAndUIDBlocks := toCut[0:32]
	validlyPaddedTrailingBlocks := toCut[32:]

	elevatedProfile := append(append(encryptedEmailAndUIDBlocks, adminBlock...), validlyPaddedTrailingBlocks...)

	return decryptAndGetRole(elevatedProfile)
}
