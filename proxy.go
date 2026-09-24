package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/SkyFetch0/gomitm"
)

func serveHTTPProxy(addr string, eng *gomitm.Engine) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("http-proxy: ", err)
	}
	log.Printf("HTTP CONNECT proxy on %s", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go handleHTTPProxyConn(c, eng)
	}
}

func handleHTTPProxyConn(c net.Conn, eng *gomitm.Engine) {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		c.Close()
		return
	}
	if strings.EqualFold(req.Method, "CONNECT") {
		host := req.Host
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, "443")
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		bc := &bufioConn{r: br, c: c}
		eng.Handle(bc, stripHostPort(req.Host), host, false)
		return
	}
	// plaintext HTTP proxy
	dst := req.Host
	if _, _, err := net.SplitHostPort(dst); err != nil {
		dst = net.JoinHostPort(dst, "80")
	}
	host := stripHostPort(req.Host)
	up, err := net.DialTimeout("tcp", dst, 15*time.Second)
	if err != nil {
		http.Error(&hijackRW{c}, "upstream dial failed", 502)
		c.Close()
		return
	}
	req.RequestURI = ""
	if err := req.Write(up); err != nil {
		up.Close()
		c.Close()
		return
	}
	go func() { io.Copy(up, br); up.Close() }()
	io.Copy(c, up)
	c.Close()
	_ = host
}

type bufioConn struct {
	r *bufio.Reader
	c net.Conn
}

func (b *bufioConn) Read(p []byte) (int, error)         { return b.r.Read(p) }
func (b *bufioConn) Write(p []byte) (int, error)        { return b.c.Write(p) }
func (b *bufioConn) Close() error                       { return b.c.Close() }
func (b *bufioConn) LocalAddr() net.Addr                { return b.c.LocalAddr() }
func (b *bufioConn) RemoteAddr() net.Addr               { return b.c.RemoteAddr() }
func (b *bufioConn) SetDeadline(t time.Time) error      { return b.c.SetDeadline(t) }
func (b *bufioConn) SetReadDeadline(t time.Time) error  { return b.c.SetReadDeadline(t) }
func (b *bufioConn) SetWriteDeadline(t time.Time) error { return b.c.SetWriteDeadline(t) }

type hijackRW struct{ net.Conn }

func (h *hijackRW) Header() http.Header         { return make(http.Header) }
func (h *hijackRW) Write(b []byte) (int, error) { return h.Conn.Write(b) }
func (h *hijackRW) WriteHeader(int)             {}

func stripHostPort(h string) string {
	host, _, err := net.SplitHostPort(h)
	if err != nil {
		return h
	}
	return host
}

func serveSOCKS5(addr string, eng *gomitm.Engine) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("socks5: ", err)
	}
	log.Printf("SOCKS5 on %s", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSOCKS5(c, eng)
	}
}

func handleSOCKS5(c net.Conn, eng *gomitm.Engine) {
	defer func() {
		if recover() != nil {
			c.Close()
		}
	}()
	br := bufio.NewReader(c)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		c.Close()
		return
	}
	if hdr[0] != 0x05 {
		c.Close()
		return
	}
	nmethods := int(hdr[1])
	if _, err := io.ReadFull(br, make([]byte, nmethods)); err != nil {
		c.Close()
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		c.Close()
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		c.Close()
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		c.Close()
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(br, addr); err != nil {
			c.Close()
			return
		}
		host = net.IP(addr).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			c.Close()
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(br, name); err != nil {
			c.Close()
			return
		}
		host = string(name)
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(br, addr); err != nil {
			c.Close()
			return
		}
		host = net.IP(addr).String()
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		c.Close()
		return
	}
	portb := make([]byte, 2)
	if _, err := io.ReadFull(br, portb); err != nil {
		c.Close()
		return
	}
	port := int(portb[0])<<8 | int(portb[1])
	dst := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	bc := &bufioConn{r: br, c: c}
	eng.Handle(bc, host, dst, false)
}
