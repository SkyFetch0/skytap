package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SkyFetch0/gomitm"
)

func authedMux(t *testing.T, token string) *httptest.Server {
	t.Helper()
	pem := []byte("-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n")
	h := adminMux(t.TempDir(), NewRegistry(), NewRuleEngine(), token, NewHub(), pem, "127.0.0.1:8080", nil)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestWSRejectsMissingAndWrongToken(t *testing.T) {
	srv := authedMux(t, "secret")
	wsUpgrade := func(url string) *http.Response {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := wsUpgrade(srv.URL + "/ws")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("no token: want 401 got %d", resp.StatusCode)
	}

	resp = wsUpgrade(srv.URL + "/ws?token=yanlis")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("wrong token: want 401 got %d", resp.StatusCode)
	}

	resp = wsUpgrade(srv.URL + "/ws?token=")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("empty token: want 401 got %d", resp.StatusCode)
	}
}

func TestRESTIgnoresQueryTokenRequiresBearer(t *testing.T) {
	srv := authedMux(t, "secret")
	resp, err := http.Get(srv.URL + "/domains?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("query token on REST must 401, got %d", resp.StatusCode)
	}
}

func TestMetaPublicNoTokenLeakCAProtected(t *testing.T) {
	srv := authedMux(t, "super-secret-token")
	resp, err := http.Get(srv.URL + "/meta")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if strings.Contains(string(b), "super-secret-token") {
		t.Fatalf("token leaked in /meta: %s", b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["auth_required"] != true {
		t.Fatalf("%v", m)
	}

	resp, err = http.Get(srv.URL + "/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("ca without bearer: %d", resp.StatusCode)
	}
}

func TestWSAcceptsValidQueryToken(t *testing.T) {
	srv := authedMux(t, "secret")
	host := strings.TrimPrefix(srv.URL, "http://")
	c, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET /ws?token=secret HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("want 101 got %q", status)
	}
	_ = sha1.Sum([]byte(key + wsGUID))
	_ = base64.StdEncoding.EncodeToString
}

func TestHubPublishJSONToTwo(t *testing.T) {
	h := NewHub()
	p1a, p1b := net.Pipe()
	p2a, p2b := net.Pipe()
	t.Cleanup(func() { p1a.Close(); p1b.Close(); p2a.Close(); p2b.Close() })
	h.add(&wsConn{c: p1a})
	h.add(&wsConn{c: p2a})

	got := make(chan string, 2)
	read := func(r net.Conn) {
		br := bufio.NewReader(r)
		b, err := readWSFrame(br)
		if err != nil {
			got <- ""
			return
		}
		got <- string(b)
	}
	go read(p1b)
	go read(p2b)
	h.Publish(gomitm.Flow{Host: "x.test", Method: "GET", Path: "/", Status: 200})
	t1 := time.After(2 * time.Second)
	var n int
	for n < 2 {
		select {
		case s := <-got:
			if !strings.Contains(s, `"type":"flow"`) || !strings.Contains(s, "x.test") {
				t.Fatalf("payload %s", s)
			}
			n++
		case <-t1:
			t.Fatalf("only %d clients got the flow", n)
		}
	}
}
