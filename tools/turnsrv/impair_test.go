package turnsrv

import (
	"net"
	"sync"
	"testing"
	"time"

	"faf-main/tools/relay"
)

// recordingConn counts what reaches the socket and when.
type recordingConn struct {
	net.PacketConn
	mu    sync.Mutex
	times []time.Time
}

func (r *recordingConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	r.mu.Lock()
	r.times = append(r.times, time.Now())
	r.mu.Unlock()
	return len(p), nil
}

func (r *recordingConn) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.times)
}

func TestImpairedConn(t *testing.T) {
	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	rec := &recordingConn{}
	c := &impairedConn{PacketConn: rec, shared: newImpairment()}

	// Untouched by default.
	for i := 0; i < 100; i++ {
		_, _ = c.WriteTo([]byte{1}, to)
	}
	if n := rec.count(); n != 100 {
		t.Fatalf("pass-through: %d of 100 written", n)
	}

	// Blocked: nothing goes out, and the sender sees no error.
	c.shared.set(relay.Impairment{Blocked: true})
	if n, err := c.WriteTo([]byte{1, 2}, to); n != 2 || err != nil {
		t.Fatalf("blocked write reported %d, %v", n, err)
	}
	time.Sleep(20 * time.Millisecond)
	if n := rec.count(); n != 100 {
		t.Fatalf("blocked: %d written, want 100", n)
	}

	// 30 % loss over 2000 datagrams.
	c.shared.set(relay.Impairment{Loss: 0.3})
	for i := 0; i < 2000; i++ {
		_, _ = c.WriteTo([]byte{1}, to)
	}
	got := rec.count() - 100
	if got < 1250 || got > 1550 {
		t.Fatalf("30%% loss: %d of 2000 went out", got)
	}

	// Latency: the datagram leaves no earlier than asked.
	c.shared.set(relay.Impairment{Latency: 40 * time.Millisecond})
	before := rec.count()
	start := time.Now()
	_, _ = c.WriteTo([]byte{1}, to)
	time.Sleep(10 * time.Millisecond)
	if rec.count() != before {
		t.Fatal("latency: sent before its delay")
	}
	time.Sleep(80 * time.Millisecond)
	if rec.count() != before+1 {
		t.Fatal("latency: not sent after its delay")
	}
	rec.mu.Lock()
	elapsed := rec.times[len(rec.times)-1].Sub(start)
	rec.mu.Unlock()
	if elapsed < 40*time.Millisecond {
		t.Fatalf("latency: left after %v", elapsed)
	}
}

// A relay socket leaves writes to the server's own relay addresses alone: the
// client-facing write after them shapes that path.
func TestRelaySocketSkipsOwnAddresses(t *testing.T) {
	own := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}
	player := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 6000}
	shared := newImpairment()
	shared.relays.Store(own.String(), struct{}{})
	shared.set(relay.Impairment{Blocked: true})
	rec := &recordingConn{}
	c := &impairedConn{PacketConn: rec, shared: shared, relay: true}
	_, _ = c.WriteTo([]byte{1}, own)
	_, _ = c.WriteTo([]byte{1}, player)
	if n := rec.count(); n != 1 {
		t.Fatalf("%d written, want only the one to the server's own relay address", n)
	}
}
