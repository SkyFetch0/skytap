package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/SkyFetch0/gomitm"
)

type HostSSLPolicy struct {
	Host        string `json:"host"`
	Kit         bool   `json:"kit"`
	Impersonate bool   `json:"impersonate"`
	Pin         string `json:"pin"`
	Verify      string `json:"verify"`
	Captured    bool   `json:"captured"`
	SPKI        string `json:"spki,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
}

type SSLKitStore struct {
	mu      sync.Mutex
	dataDir string
	confDir string
	hosts   map[string]HostSSLPolicy
}

func NewSSLKitStore(dataDir, confDir string) *SSLKitStore {
	s := &SSLKitStore{
		dataDir: dataDir,
		confDir: confDir,
		hosts:   map[string]HostSSLPolicy{},
	}
	s.load()
	_ = s.writeClientConf()
	return s
}

func (s *SSLKitStore) path() string {
	return filepath.Join(s.dataDir, "sslkit.json")
}

func (s *SSLKitStore) load() {
	b, err := os.ReadFile(s.path())
	if err != nil {
		return
	}
	var m map[string]HostSSLPolicy
	if json.Unmarshal(b, &m) == nil && m != nil {
		s.hosts = m
	}
}

func (s *SSLKitStore) persist() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persistLocked()
}

func (s *SSLKitStore) persistLocked() {
	if s.dataDir == "" {
		return
	}
	_ = os.MkdirAll(s.dataDir, 0o755)
	b, err := json.MarshalIndent(s.hosts, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(s.path(), b, 0o644)
	_ = s.writeClientConfLocked()
}

func (s *SSLKitStore) Get(host string) HostSSLPolicy {
	host = strings.ToLower(strings.TrimSpace(host))
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.hosts[host]
	if !ok {
		return HostSSLPolicy{Host: host, Pin: "off", Verify: "ca"}
	}
	p = s.refreshLocked(p)
	return p
}

func (s *SSLKitStore) All() []HostSSLPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]HostSSLPolicy, 0, len(s.hosts))
	for _, p := range s.hosts {
		out = append(out, s.refreshLocked(p))
	}
	return out
}

func (s *SSLKitStore) Put(p HostSSLPolicy) HostSSLPolicy {
	p.Host = strings.ToLower(strings.TrimSpace(p.Host))
	if p.Pin == "" {
		p.Pin = "off"
	}
	if p.Verify == "" {
		p.Verify = "ca"
	}
	s.mu.Lock()
	cur := s.hosts[p.Host]
	if p.SPKI == "" {
		p.SPKI = cur.SPKI
		p.Subject = cur.Subject
		p.Issuer = cur.Issuer
		p.Captured = cur.Captured
	}
	p = s.refreshLocked(p)
	s.hosts[p.Host] = p
	s.persistLocked()
	s.mu.Unlock()
	return p
}

func (s *SSLKitStore) refreshLocked(p HostSSLPolicy) HostSSLPolicy {
	dir := gomitm.OriginDumpDir()
	if dir == "" {
		return p
	}
	pemPath := filepath.Join(dir, p.Host+".pem")
	b, err := os.ReadFile(pemPath)
	if err != nil {
		p.Captured = false
		return p
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return p
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return p
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	p.SPKI = base64.StdEncoding.EncodeToString(sum[:])
	p.Subject = c.Subject.String()
	p.Issuer = c.Issuer.String()
	p.Captured = true
	s.hosts[p.Host] = p
	return p
}

func (s *SSLKitStore) Capture(host, dst string) (HostSSLPolicy, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return HostSSLPolicy{}, fmt.Errorf("host required")
	}
	if err := gomitm.DumpOriginChain(host, dst, true); err != nil {
		return HostSSLPolicy{}, err
	}
	s.mu.Lock()
	p := s.hosts[host]
	p.Host = host
	if p.Pin == "" {
		p.Pin = "off"
	}
	if p.Verify == "" {
		p.Verify = "ca"
	}
	p = s.refreshLocked(p)
	s.hosts[host] = p
	s.persistLocked()
	s.mu.Unlock()
	return p, nil
}

func (s *SSLKitStore) ImpersonateEnabled(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.hosts[host]
	return ok && p.Impersonate
}

func (s *SSLKitStore) writeClientConf() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeClientConfLocked()
}

func (s *SSLKitStore) writeClientConfLocked() error {
	dir := s.confDir
	if dir == "" {
		dir = "/certs"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var kit, imp, pins, vers []string
	for _, p := range s.hosts {
		if p.Kit {
			kit = append(kit, p.Host)
		}
		if p.Impersonate {
			imp = append(imp, p.Host)
		}
		if p.Pin != "" {
			pins = append(pins, p.Host+"="+p.Pin)
		}
		if p.Verify != "" {
			vers = append(vers, p.Host+"="+p.Verify)
		}
	}
	body := fmt.Sprintf(
		"SKYTAP_SSL_CA=/certs/ca.crt\nSKYTAP_SSL_PROXY=http://skytap:8080\nSKYTAP_SSL_ORIGIN_CERT_DIR=/certs/origin-cache\nSKYTAP_SSL_KIT_HOSTS=%s\nSKYTAP_SSL_IMPERSONATE_HOSTS=%s\nSKYTAP_SSL_IMPERSONATE=%s\nSKYTAP_SSL_PIN_BY_HOST=%s\nSKYTAP_SSL_VERIFY_BY_HOST=%s\n",
		strings.Join(kit, ","), strings.Join(imp, ","),
		boolEnv(len(imp) > 0), strings.Join(pins, ","), strings.Join(vers, ","),
	)
	return os.WriteFile(filepath.Join(dir, "skytap-ssl.conf"), []byte(body), 0o644)
}

func boolEnv(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
