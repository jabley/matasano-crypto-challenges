package main

import (
	"reflect"
	"testing"
)

func assertEqual(t *testing.T, expected, actual interface{}) {
	if expected == nil || actual == nil {

		if actual != expected {
			t.Fatalf("Expected %q: Actual: %q\n", expected, actual)
		}
		return
	}
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Expected %q: Actual: %q\n", expected, actual)
	}
}
