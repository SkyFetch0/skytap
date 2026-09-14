package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminTokenRequired(t *testing.T) {
	reg := NewRegistry()
	rules := NewRuleEngine()
	h := adminMux(t.TempDir(), reg, rules, "secret", NewHub(), nil, "127.0.0.1:8080", nil)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/domains")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("got %d", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", srv.URL+"/domains", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestIsLoopback(t *testing.T) {
	if !isLoopback("127.0.0.1:8080") || !isLoopback("localhost:1") {
		t.Fatal("loopback")
	}
	if isLoopback("0.0.0.0:8080") || isLoopback(":8080") {
		t.Fatal("must not treat wildcard as loopback")
	}
}
