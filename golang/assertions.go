package main

import (
	"reflect"
	"testing"
)

func assertEqual(t *testing.T, expected, actual interface{}) {
	t.Helper()
	if expected == nil || actual == nil {

		if actual != expected {
			fail(t, expected, actual)
		}
		return
	}
	if !reflect.DeepEqual(expected, actual) {
		fail(t, expected, actual)
	}
}

func fail(t *testing.T, expected, actual interface{}) {
	t.Helper()
	t.Fatalf("Expected\n%#v\nActual:\n%#v\n", expected, actual)
}
