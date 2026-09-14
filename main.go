package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/SkyFetch0/gomitm"
	"github.com/SkyFetch0/skydst"
)

func main() {
	listen := flag.String("listen", ":3128", "transparent proxy listen address")
	httpProxy := flag.String("http-proxy", "", "explicit HTTP CONNECT proxy (e.g. :8080); empty = disabled")
	socks := flag.String("socks", "", "explicit SOCKS5 proxy (e.g. :1080); empty = disabled")
	admin := flag.String("admin", "127.0.0.1:8080", "admin/MCP bind (default localhost; never 0.0.0.0 without -admin-token)")
	adminToken := flag.String("admin-token", os.Getenv("SKYTAP_ADMIN_TOKEN"), "Bearer token for admin+MCP (required unless bind is loopback)")
	data := flag.String("data", "/data", "persist dir (CA + state.json + rules.json)")
	keyLogPath := flag.String("keylog", os.Getenv("SSLKEYLOGFILE"), "NSS TLS key log path (SSLKEYLOGFILE)")
	verifyUp := flag.Bool("verify-upstream", false, "verify origin TLS with the system CA (default skip)")
	install := flag.Bool("install-rules", true, "install nft/iptables capture rules")
	mode := flag.String("mode", "output", "output|prerouting")
	ports := flag.String("ports", "80,443", "comma-separated TCP ports to redirect")
	excludeNets := flag.String("exclude-nets", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", "comma-separated CIDRs skipped (RETURN)")
	flag.Parse()

	caDir := filepath.Join(*data, "ca")
	ca, err := gomitm.LoadOrCreateCA(caDir)
	if err != nil {
		log.Fatal(err)
	}

	reg := NewRegistry()
	rules := NewRuleEngine()
	if err := loadPersist(*data, reg, rules); err != nil {
		log.Fatal(err)
	}
	seed(reg, rules)
	if h := os.Getenv("SKYTAP_INTERCEPT_HOSTS"); h != "" {
		for _, name := range splitCSV(h) {
			reg.SetState(name, StateIntercepted)
		}
		_ = savePersist(*data, reg, rules)
	}
	_ = savePersist(*data, reg, rules)

	odir := os.Getenv("SKYTAP_ORIGIN_CERT_DIR")
	if odir == "" {
		odir = "/certs/origin-cache"
	}
	if err := os.MkdirAll(odir, 0o755); err == nil {
		gomitm.SetOriginDumpDir(odir)
		log.Printf("origin cert dump %s", odir)
	}
	kit := NewSSLKitStore(*data, "/certs")
	hub := NewHub()
	app := &App{reg: reg, rules: rules, hub: hub, dataDir: *data, kit: kit, pinBypass: loadPinBypass(*data)}
	eng := gomitm.New(ca, app).WithUpstreamVerify(*verifyUp)
	if *keyLogPath != "" {
		if err := os.MkdirAll(filepath.Dir(*keyLogPath), 0o755); err != nil {
			log.Fatal(err)
		}
		kl, err := os.OpenFile(*keyLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		eng = eng.WithKeyLog(io.Writer(kl))
		log.Printf("TLS key log %s", *keyLogPath)
	}
	restoreCATrust(ca.CACertPEM(), *data)
	pem := ca.CACertPEM()
	_ = os.WriteFile(filepath.Join(*data, "ca", "ca.crt"), pem, 0o644)
	if st, err := os.Stat("/certs"); err == nil && st.IsDir() {
		_ = os.WriteFile("/certs/ca.crt", pem, 0o644)
		_ = os.WriteFile("/certs/ca.pem", pem, 0o644)
	}

	if *install {
		m := skydst.OutputRedirect
		if *mode == "prerouting" {
			m = skydst.PreroutingRedirect
		}
		spec := skydst.RuleSpec{
			ProxyPort:   mustPort(*listen),
			Ports:       parseInts(*ports),
			ExcludeUID:  os.Getuid(),
			ExcludeNets: splitCSV(*excludeNets),
			Mode:        m,
		}
		if err := skydst.InstallRules(spec); err != nil {
			log.Printf("InstallRules: %v (continuing; capture may be manual)", err)
		}
		go func() {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
			<-ch
			_ = skydst.RemoveRules(spec)
			os.Exit(0)
		}()
	}

	go func() {
		log.Printf("admin API on %s", *admin)
		h := adminMux(*data, reg, rules, *adminToken, hub, ca.CACertPEM(), *admin, app)
		if !isLoopback(*admin) && *adminToken == "" && os.Getenv("SKYTAP_ALLOW_OPEN_ADMIN") != "1" {
			log.Fatal("refusing non-loopback admin bind without -admin-token / SKYTAP_ADMIN_TOKEN")
		}
		if err := http.ListenAndServe(*admin, h); err != nil {
			log.Fatal(err)
		}
	}()
	if *httpProxy != "" {
		go serveHTTPProxy(*httpProxy, eng)
	}
	if *socks != "" {
		go serveSOCKS5(*socks, eng)
	}

	ln, err := skydst.Listen(*listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("proxy on %s", *listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go func(c *skydst.Conn) {
			log.Printf("accept orig-dst=%q remote=%s", c.OriginalDst, c.RemoteAddr())
			eng.Handle(c, "", c.OriginalDst, false)
		}(c)
	}
}

func seed(reg *Registry, rules *RuleEngine) {
	if _, ok := reg.snapshot()["check.spy.net"]; !ok {
		reg.SetState("check.spy.net", StateMocked)
	}
	has := false
	for _, r := range rules.All() {
		if r.Host == "check.spy.net" {
			has = true
			break
		}
	}
	if !has {
		rules.Add(Rule{
			Host:   "check.spy.net",
			Path:   "/",
			Method: "GET",
			Status: 200,
			Body:   `{"license":"active"}`,
			Type:   "application/json",
		})
	}
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseInts(s string) []int {
	var out []int
	for _, p := range splitCSV(s) {
		n := 0
		ok := true
		for _, c := range p {
			if c < '0' || c > '9' {
				ok = false
				break
			}
			n = n*10 + int(c-'0')
		}
		if ok && n > 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return []int{80, 443}
	}
	return out
}

func mustPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 3128
	}
	var n int
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return n
}
