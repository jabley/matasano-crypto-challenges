package main

import "unicode"

func isEnglishCharacter(c byte) bool {
	return isAlpha(c) || isSpace(c) || isDigit(c)
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isAlpha(c byte) bool {
	return isUpper(c) || isLower(c)
}

func isUpper(c byte) bool {
	return c >= 'A' && c <= 'Z'
}

func isLower(c byte) bool {
	return c >= 'a' && c <= 'z'
}

func isPunctuation(c byte) bool {
	switch c {
	case '\'', '"', '.', ',', ':', ';':
		return true
	default:
		return false
	}
}

func isSpace(c byte) bool {
	return unicode.IsSpace(rune(c))
}

func scoreText(buf []byte) int {
	total := 0
	for _, b := range buf {
		if isEnglishCharacter(b) {
			total++
		}
	}

	if total > len(buf)-10 {
		// fmt.Printf("%v scored %v\n", total, string(buf))
	}

	return total
}
