package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"faf-main/tools/rttprobe"
)

func testEcho(t *testing.T) *rttEcho {
	t.Helper()
	// An explicit loopback address: some Windows accounts drop UDP sent to a socket bound to every address.
	e, err := listenRTTEcho("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.serve()
	t.Cleanup(func() { _ = e.close() })
	return e
}

func TestRTTEchoRoundTrip(t *testing.T) {
	e := testEcho(t)
	r := rttprobe.Probe(context.Background(), e.addr().String(), rttprobe.Options{Count: 5, Interval: 5 * time.Millisecond,
		Timeout: 500 * time.Millisecond, Local: "127.0.0.1"})
	if r.Sent != 5 || r.Received != 5 || r.LossPct != 0 || r.MedianMs < 0 || r.MedianMs > 100 {
		t.Fatalf("probe: %+v", r)
	}
	if e.answered.Load() != 5 || e.dropped.Load() != 0 {
		t.Fatalf("counts: answered %d, dropped %d", e.answered.Load(), e.dropped.Load())
	}
}

// send writes raw datagrams to the echo and answers what came back within wait.
func send(t *testing.T, e *rttEcho, packets [][]byte, wait time.Duration) [][]byte {
	t.Helper()
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, e.addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, p := range packets {
		if _, err := c.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	out := [][]byte{}
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return out
		}
		out = append(out, append([]byte{}, buf[:n]...))
	}
}

func TestRTTEchoDropsMalformed(t *testing.T) {
	e := testEcho(t)
	probe := rttprobe.Encode(rttprobe.KindProbe, 42, 1)
	long := append(append([]byte{}, probe...), make([]byte, 100)...)
	wrongMagic := append([]byte{}, probe...)
	wrongMagic[0] = 'G'
	tail := append([]byte{}, probe...)
	tail[30] = 9
	reply := rttprobe.Encode(rttprobe.KindReply, 42, 1)
	got := send(t, e, [][]byte{probe[:20], long, wrongMagic, tail, reply, []byte("GET / HTTP/1.1\r\n\r\n")}, 300*time.Millisecond)
	if len(got) != 0 {
		t.Fatalf("answered %d malformed packets: %q", len(got), got)
	}
	if e.dropped.Load() != 6 || e.answered.Load() != 0 {
		t.Fatalf("dropped %d, answered %d", e.dropped.Load(), e.answered.Load())
	}
	// A good probe still gets exactly its own size back.
	got = send(t, e, [][]byte{probe}, 300*time.Millisecond)
	if len(got) != 1 || len(got[0]) != len(probe) {
		t.Fatalf("good probe: %q", got)
	}
	if kind, s, seq, ok := rttprobe.Parse(got[0]); !ok || kind != rttprobe.KindReply || s != 42 || seq != 1 {
		t.Fatalf("reply: %v", got[0])
	}
}

func TestRTTEchoRateLimit(t *testing.T) {
	e := testEcho(t)
	clock := time.Unix(1_000_000, 0)
	e.mu.Lock()
	e.now = func() time.Time { return clock }
	e.mu.Unlock()
	probes := [][]byte{}
	for i := 0; i < 30; i++ {
		probes = append(probes, rttprobe.Encode(rttprobe.KindProbe, 7, uint64(i)))
	}
	got := send(t, e, probes, 300*time.Millisecond)
	if len(got) != int(echoBurst) || e.limited.Load() != 30-int64(echoBurst) {
		t.Fatalf("a burst of 30 from one address: %d answered, %d limited", len(got), e.limited.Load())
	}
	// One second later the address has rate tokens again.
	e.mu.Lock()
	clock = clock.Add(time.Second)
	e.mu.Unlock()
	got = send(t, e, probes[:15], 300*time.Millisecond)
	if len(got) != int(echoRate) {
		t.Fatalf("after a second: %d answered, want %d", len(got), int(echoRate))
	}
	// The global limit holds for every address together.
	e.mu.Lock()
	e.global = bucket{tokens: 0, at: clock}
	e.globalRate = 0
	clock = clock.Add(time.Hour)
	e.mu.Unlock()
	if got = send(t, e, probes[:3], 300*time.Millisecond); len(got) != 0 {
		t.Fatalf("over the global limit: %d answered", len(got))
	}
}

func TestRTTEchoAddressAndAPI(t *testing.T) {
	cases := []struct{ flag, want string }{
		{"", "0.0.0.0:27180"}, {"off", ""}, {"27300", "0.0.0.0:27300"}, {"203.0.113.5:4000", "203.0.113.5:4000"},
	}
	for _, c := range cases {
		got, err := rttEchoAddress(c.flag, "127.0.0.1:27180", "0.0.0.0")
		if err != nil || got != c.want {
			t.Errorf("--rtt-echo %q: %q %v, want %q", c.flag, got, err, c.want)
		}
	}
	for _, bad := range []string{"70000", "nope"} {
		if _, err := rttEchoAddress(bad, "127.0.0.1:27180", "0.0.0.0"); err == nil {
			t.Errorf("--rtt-echo %q accepted", bad)
		}
	}
	m := testManager(t)
	a := &api{token: "0123456789abcdef0123", m: m, maps: m.maps, procDir: t.TempDir(), hostName: "h", rttEcho: "203.0.113.5:27180", echo: testEcho(t)}
	for _, path := range []string{"/api/v1/host", "/api/v1/public/pool"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer 0123456789abcdef0123")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		var doc map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &doc)
		if host, ok := doc["host"].(map[string]any); ok {
			doc = host
			if _, ok := doc["rtt_echo_counts"].(map[string]any); !ok {
				t.Errorf("%s: no echo counts: %s", path, w.Body)
			}
		}
		if doc["rtt_echo"] != "203.0.113.5:27180" {
			t.Errorf("%s: rtt_echo %v", path, doc["rtt_echo"])
		}
	}
}
