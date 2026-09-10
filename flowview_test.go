package main

import (
	"encoding/base64"
	"testing"

	"github.com/SkyFetch0/gomitm"
)

func TestEncodeBodyUTF8AndBase64(t *testing.T) {
	s, e := encodeBody([]byte(`{"ok":true}`))
	if e != "utf8" || s != `{"ok":true}` {
		t.Fatalf("%q %s", s, e)
	}
	bin := []byte{0xff, 0xfe, 0x00, 0x01}
	s, e = encodeBody(bin)
	if e != "base64" {
		t.Fatalf("enc=%s", e)
	}
	got, err := base64.StdEncoding.DecodeString(s)
	if err != nil || string(got) != string(bin) {
		t.Fatal(err)
	}
	views := flowViews([]gomitm.Flow{{ResBody: bin}})
	if views[0].ResEncoding != "base64" {
		t.Fatal(views[0].ResEncoding)
	}
}
