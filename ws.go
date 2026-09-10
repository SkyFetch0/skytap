package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type wsConn struct {
	c    net.Conn
	wmu  sync.Mutex
	done chan struct{}
}

func (c *wsConn) send(payload []byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = writeWSFrame(c.c, 1, payload)
}

func writeWSFrame(w io.Writer, opcode byte, payload []byte) error {
	n := len(payload)
	var hdr []byte
	if n < 126 {
		hdr = []byte{0x80 | opcode, byte(n)}
	} else if n < 65536 {
		hdr = []byte{0x80 | opcode, 126, byte(n >> 8), byte(n)}
	} else {
		hdr = make([]byte, 10)
		hdr[0] = 0x80 | opcode
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func handleWS(w http.ResponseWriter, r *http.Request, hub *Hub, reg *Registry) {
	if r.Header.Get("Upgrade") != "websocket" && r.Header.Get("Upgrade") != "WebSocket" {
		http.Error(w, "upgrade required", 400)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", 500)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	acc := wsAccept(r.Header.Get("Sec-WebSocket-Key"))
	_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+acc+"\r\n\r\n")
	_ = bufrw.Flush()

	wc := &wsConn{c: conn, done: make(chan struct{})}
	hub.add(wc)
	defer func() {
		hub.remove(wc)
		conn.Close()
	}()

	// initial snapshot: last flows across known hosts
	var all []flowView
	for _, d := range reg.Domains() {
		all = append(all, flowViews(reg.Flows(d.Host))...)
	}
	snap, _ := json.Marshal(map[string]any{"type": "snapshot", "flows": all})
	wc.send(snap)

	br := bufio.NewReader(conn)
	for {
		if _, err := readWSFrame(br); err != nil {
			return
		}
	}
}

func readWSFrame(br *bufio.Reader) ([]byte, error) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		return nil, err
	}
	masked := h[1]&0x80 != 0
	n := int(h[1] & 0x7f)
	if n == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return nil, err
		}
		n = int(binary.BigEndian.Uint16(ext[:]))
	} else if n == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return nil, err
		}
		n = int(binary.BigEndian.Uint64(ext[:]))
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(br, mask[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	opcode := h[0] & 0x0f
	if opcode == 8 {
		return nil, io.EOF
	}
	return payload, nil
}
