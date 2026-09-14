package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/SkyFetch0/gomitm"
)

func TestAdminSeedDomainsAndStateAndRulesAndPersist(t *testing.T) {
	dir := t.TempDir()
	reg := NewRegistry()
	rules := NewRuleEngine()
	seed(reg, rules)
	if err := savePersist(dir, reg, rules); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(adminMux(dir, reg, rules, "", NewHub(), nil, "127.0.0.1:8080", nil))
	t.Cleanup(srv.Close)

	// seed MOCKED
	var domains []DomainInfo
	getJSON(t, srv.URL+"/domains", &domains)
	found := false
	for _, d := range domains {
		if d.Host == "check.spy.net" && d.State == StateMocked {
			found = true
		}
	}
	if !found {
		t.Fatalf("seed missing: %+v", domains)
	}

	// /state changes
	getJSON(t, srv.URL+"/state?host=api.example.com&state=intercepted", &map[string]string{})
	if reg.State("api.example.com") != StateIntercepted {
		t.Fatalf("state=%s", reg.State("api.example.com"))
	}

	// POST /rules then OnRequest matches
	body := []byte(`{"host":"api.example.com","path":"/v1","method":"GET","status":200,"body":"{\"ok\":true}","content_type":"application/json"}`)
	resp, err := http.Post(srv.URL+"/rules", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST /rules %d", resp.StatusCode)
	}
	getJSON(t, srv.URL+"/state?host=api.example.com&state=MOCKED", &map[string]string{})
	app := &App{reg: reg, rules: rules}
	req, _ := http.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	got := app.OnRequest("api.example.com", req)
	if got == nil {
		t.Fatal("expected mock response")
	}

	// persist files exist with enums as strings
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("INTERCEPTED")) && !bytes.Contains(raw, []byte("MOCKED")) {
		t.Fatalf("state.json missing enum strings: %s", raw)
	}

	// reload into empty registry/engine
	reg2 := NewRegistry()
	rules2 := NewRuleEngine()
	if err := loadPersist(dir, reg2, rules2); err != nil {
		t.Fatal(err)
	}
	if reg2.State("check.spy.net") != StateMocked {
		t.Fatalf("reload check.spy.net=%s", reg2.State("check.spy.net"))
	}
	if reg2.State("api.example.com") != StateMocked {
		t.Fatalf("reload api.example.com=%s", reg2.State("api.example.com"))
	}
	req2, _ := http.NewRequest("GET", "http://api.example.com/v1", nil)
	app2 := &App{reg: reg2, rules: rules2}
	if app2.OnRequest("api.example.com", req2) == nil {
		t.Fatal("reloaded rules did not match")
	}
	_ = gomitm.Passthrough
}

func TestDeleteDomainAndClearHistory(t *testing.T) {
	dir := t.TempDir()
	reg := NewRegistry()
	rules := NewRuleEngine()
	reg.SetState("gone.example", StateObserved)
	reg.AddFlow(gomitm.Flow{Host: "gone.example", Path: "/"})
	srv := httptest.NewServer(adminMux(dir, reg, rules, "", NewHub(), nil, "127.0.0.1:8080", nil))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/history?scope=flows&host=gone.example", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("clear flows %d", resp.StatusCode)
	}
	if len(reg.Flows("gone.example")) != 0 {
		t.Fatal("flows still present")
	}

	req, _ = http.NewRequest(http.MethodDelete, srv.URL+"/domains?host=gone.example", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("delete domain %d", resp.StatusCode)
	}
	for _, d := range reg.Domains() {
		if d.Host == "gone.example" {
			t.Fatal("domain still listed")
		}
	}

	reg.SetState("x", StateObserved)
	req, _ = http.NewRequest(http.MethodDelete, srv.URL+"/history?scope=all", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(reg.Domains()) != 0 {
		t.Fatalf("reset left %d domains", len(reg.Domains()))
	}
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("%s -> %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}
