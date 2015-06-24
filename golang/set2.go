package main

func Challenge9() (string, error) {
	out, err := pkcs7([]byte("YELLOW SUBMARINE"), 20)
	return string(out), err
}
