package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUIAndCAAndMeta(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n")
	h := adminMux(t.TempDir(), NewRegistry(), NewRuleEngine(), "", NewHub(), pem, "127.0.0.1:8080")
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "SkyTap") {
		t.Fatalf("ui %d %s", resp.StatusCode, b[:min(80, len(b))])
	}

	resp, err = http.Get(srv.URL + "/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != string(pem) {
		t.Fatalf("ca %q", b)
	}

	resp, err = http.Get(srv.URL + "/domains")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}
