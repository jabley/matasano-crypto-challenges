package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPadPKCS7(t *testing.T) {
	for i := 0; i < 16; i++ {
		t.Run(fmt.Sprintf("input size %2d", i), func(t *testing.T) {
			buf := bytes.Repeat([]byte{byte('A')}, i)
			padded := padPKCS7(buf, 16)
			assertEqual(t, len(padded), 16)
		})
	}

	buf := bytes.Repeat([]byte{byte('A')}, 16)
	padded := padPKCS7(buf, 16)
	assertEqual(t, len(padded), 32)
}

func TestUnpadPKCS7(t *testing.T) {
	assertEqual(t, isPKCS7Padded(nil, 16), false)
	assertEqual(t, isPKCS7Padded([]byte{}, 16), false)

	for i := 0; i < 34; i++ {
		t.Run(fmt.Sprintf("input size %2d bytes", i), func(t *testing.T) {
			assertEqual(t, isPKCS7Padded(padPKCS7(bytes.Repeat([]byte{0x01}, i), 16), 16), true)
		})
	}
}
