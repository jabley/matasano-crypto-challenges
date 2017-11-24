package main

import "math/bits"

func hammingDistance(a, b string) int {
	return editDistance([]byte(a), []byte(b))
}

func editDistance(a, b []byte) int {
	dist := 0
	for i := range a {
		dist += bits.OnesCount8(a[i] ^ b[i])
	}
	return dist
}

func normalisedDistance(a, b []byte) float64 {
	return float64(editDistance(a, b)) / float64(len(a))
}
