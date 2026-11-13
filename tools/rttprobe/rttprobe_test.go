package rttprobe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestFormat(t *testing.T) {
	p := Encode(KindProbe, 0x0102030405060708, 7)
	if len(p) != PacketSize {
		t.Fatalf("size %d", len(p))
	}
	kind, s, seq, ok := Parse(p)
	if !ok || kind != KindProbe || s != 0x0102030405060708 || seq != 7 {
		t.Fatalf("parse: %d %x %d %v", kind, s, seq, ok)
	}
	r := Reply(p)
	if kind, s2, seq2, ok := Parse(r); !ok || kind != KindReply || s2 != s || seq2 != seq || len(r) != len(p) {
		t.Fatalf("reply: %v", r)
	}
	if Reply(r) != nil {
		t.Fatal("a reply is answered")
	}
	bad := map[string][]byte{"short": p[:31], "long": append(append([]byte{}, p...), 0), "empty": nil}
	for name, mutate := range map[string]func([]byte){
		"magic":    func(b []byte) { b[0] = 'X' },
		"version":  func(b []byte) { b[4] = 2 },
		"kind":     func(b []byte) { b[5] = 3 },
		"reserved": func(b []byte) { b[6] = 1 },
		"tail":     func(b []byte) { b[31] = 1 },
	} {
		b := append([]byte{}, p...)
		mutate(b)
		bad[name] = b
	}
	for name, b := range bad {
		if Reply(b) != nil {
			t.Errorf("%s: answered", name)
		}
	}
}

// echo answers probes on loopback, dropping every probe whose sequence number drop says.
func echo(t *testing.T, delay time.Duration, drop func(seq uint64) bool) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			r := Reply(buf[:n])
			if r == nil {
				continue
			}
			_, _, seq, _ := Parse(r)
			if drop != nil && drop(seq) {
				continue
			}
			time.AfterFunc(delay, func() { _, _ = c.WriteTo(r, from) })
		}
	}()
	return c.LocalAddr().String()
}

func TestProbe(t *testing.T) {
	addr := echo(t, 20*time.Millisecond, func(seq uint64) bool { return seq%4 == 1 })
	r := Probe(context.Background(), addr, Options{Count: 8, Interval: 5 * time.Millisecond, Timeout: 500 * time.Millisecond, Local: "127.0.0.1"})
	if r.Sent != 8 || r.Received != 6 || r.LossPct != 25 || r.Error != "" {
		t.Fatalf("result %+v", r)
	}
	if r.MedianMs < 19 || r.MedianMs > 200 || r.MinMs > r.MedianMs || r.MaxMs < r.MedianMs {
		t.Fatalf("times %+v", r)
	}
}

func TestProbeAllAndSilence(t *testing.T) {
	up := echo(t, 0, nil)
	silent := echo(t, 0, func(uint64) bool { return true })
	rs := ProbeAll(context.Background(), []Target{{"up", up}, {"silent", silent}}, Options{Count: 3, Interval: time.Millisecond, Timeout: 200 * time.Millisecond, Local: "127.0.0.1"})
	if rs[0].Name != "up" || !rs[0].Reached() || rs[0].LossPct != 0 {
		t.Fatalf("up: %+v", rs[0])
	}
	if rs[1].Name != "silent" || rs[1].Reached() || rs[1].LossPct != 100 || rs[1].Error == "" {
		t.Fatalf("silent: %+v", rs[1])
	}
}
