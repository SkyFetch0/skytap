package main

import "testing"

func TestDetectCAFamilyFallbackDebian(t *testing.T) {
	// On Windows CI this still returns debian as default family for hints.
	f := detectCAFamily()
	if f.CertPath == "" || f.Hint == "" {
		t.Fatalf("%+v", f)
	}
}
