package main

func stripPadding(plainText []byte) []byte {
    n := len(plainText)
    paddingLength := int(plainText[n-1])

    if n-paddingLength < 0 {
        return plainText
    }

    return plainText[:n-paddingLength]
}
