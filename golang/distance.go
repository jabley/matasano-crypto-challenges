package main

func HammingDistance(a, b string) int {
	return editDistance([]byte(a), []byte(b))
}

func editDistance(a, b []byte) int {
	dist := 0
	for i := range a {
		val := a[i] ^ b[i]
		for val != 0 {
			dist++
			val &= val - 1
		}
	}
	return dist
}

func normalisedDistance(a, b []byte) float64 {
	return float64(editDistance(a, b)) / float64(len(a))
}
