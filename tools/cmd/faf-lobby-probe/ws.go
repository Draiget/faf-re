package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// wsConn is the client side of a WebSocket (RFC 6455) with text frames only: enough for the FAF message broker,
// which carries newline-terminated JSON in text frames. No TLS (ws:// only) and no extensions.
type wsConn struct {
	c   net.Conn
	r   *bufio.Reader
	wmu sync.Mutex
}

func wsDial(rawURL, host string, timeout time.Duration) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" {
		return nil, fmt.Errorf("only ws:// is supported, got %q", u.Scheme)
	}
	addr := u.Host
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	keyRaw := make([]byte, 16)
	_, _ = rand.Read(keyRaw)
	key := base64.StdEncoding.EncodeToString(keyRaw)
	path := u.RequestURI()
	if host == "" {
		host = u.Host
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err = io.WriteString(c, req); err != nil {
		c.Close()
		return nil, err
	}
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, &http.Request{Method: "GET"})
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		c.Close()
		return nil, fmt.Errorf("websocket upgrade refused: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		c.Close()
		return nil, errors.New("websocket upgrade: bad Sec-WebSocket-Accept")
	}
	_ = c.SetDeadline(time.Time{})
	return &wsConn{c: c, r: r}, nil
}

// writeText sends one masked text frame (clients must mask).
func (w *wsConn) writeText(p []byte) error { return w.writeFrame(0x1, p) }

func (w *wsConn) writeFrame(op byte, p []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	hdr := []byte{0x80 | op}
	switch n := len(p); {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		hdr = append(append(hdr, 0x80|127), b[:]...)
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)
	body := make([]byte, len(p))
	for i := range p {
		body[i] = p[i] ^ mask[i%4]
	}
	_, err := w.c.Write(append(hdr, body...))
	return err
}

// readMessage returns the next text message's payload, answering pings and joining fragments.
func (w *wsConn) readMessage() ([]byte, error) {
	var msg []byte
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.r, h[:]); err != nil {
			return nil, err
		}
		fin, op := h[0]&0x80 != 0, h[0]&0x0F
		n := uint64(h[1] & 0x7F)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > 16<<20 {
			return nil, fmt.Errorf("websocket frame of %d bytes", n)
		}
		var mask []byte
		if h[1]&0x80 != 0 {
			mask = make([]byte, 4)
			if _, err := io.ReadFull(w.r, mask); err != nil {
				return nil, err
			}
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(w.r, p); err != nil {
			return nil, err
		}
		if mask != nil {
			for i := range p {
				p[i] ^= mask[i%4]
			}
		}
		switch op {
		case 0x8:
			return nil, io.EOF
		case 0x9:
			_ = w.writeFrame(0xA, p)
			continue
		case 0xA:
			continue
		}
		msg = append(msg, p...)
		if fin {
			return msg, nil
		}
	}
}

func (w *wsConn) Close() error {
	_ = w.writeFrame(0x8, nil)
	return w.c.Close()
}
