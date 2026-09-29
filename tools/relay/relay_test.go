package relay

import (
	"net"
	"testing"
	"time"

	"faf-main/tools/journal"
)

func udp(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func addr(c *net.UDPConn) *net.UDPAddr { return c.LocalAddr().(*net.UDPAddr) }

func read(t *testing.T, c *net.UDPConn, d time.Duration) (string, *net.UDPAddr, error) {
	t.Helper()
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(d))
	n, from, err := c.ReadFromUDP(buf)
	return string(buf[:n]), from, err
}

func TestTopologyAndImpairment(t *testing.T) {
	j, _ := journal.New("", nil)
	r := New(j, Options{})
	defer r.Close()

	gameA, gameB := udp(t), udp(t)
	defer gameA.Close()
	defer gameB.Close()
	if _, err := r.Ensure(1, 2, addr(gameA), addr(gameB)); err != nil {
		t.Fatal(err)
	}
	bForA, _ := r.AddrFor(1, 2) // where A sends to reach B
	aForB, _ := r.AddrFor(2, 1)
	dstB, _ := net.ResolveUDPAddr("udp4", bForA)

	// A -> B arrives from the address B was told A lives at.
	_, _ = gameA.WriteToUDP([]byte("hello"), dstB)
	got, from, err := read(t, gameB, time.Second)
	if err != nil || got != "hello" {
		t.Fatalf("B read %q %v", got, err)
	}
	if from.String() != aForB {
		t.Fatalf("B saw the packet from %s, expected %s", from, aForB)
	}

	// Latency applies.
	if err = r.Set(1, 2, Impairment{Latency: 80 * time.Millisecond}, false); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _ = gameA.WriteToUDP([]byte("late"), dstB)
	if _, _, err = read(t, gameB, time.Second); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 70*time.Millisecond {
		t.Fatalf("delivered after %s, expected ~80ms", d)
	}

	// Blocking drops.
	r.Isolate(2, true)
	_, _ = gameA.WriteToUDP([]byte("cut"), dstB)
	if _, _, err = read(t, gameB, 150*time.Millisecond); err == nil {
		t.Fatal("packet crossed an isolated link")
	}
	if s := r.Stats()["1->2"]; s.Blocked != 1 || s.Packets != 3 {
		t.Fatalf("stats %+v", s)
	}
}

// A latching relay learns each game's address from its traffic, as a hub
// reached over the internet must (the games are behind NAT).
// freeBlock finds n consecutive free UDP ports on loopback.
func freeBlock(t *testing.T, n int) int {
	t.Helper()
	for base := 41000; base < 60000; base += n {
		var held []*net.UDPConn
		ok := true
		for p := base; p < base+n; p++ {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
			if err != nil {
				ok = false
				break
			}
			held = append(held, c)
		}
		for _, c := range held {
			_ = c.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free port block")
	return 0
}

func TestLatchAndPortPool(t *testing.T) {
	j, _ := journal.New("", nil)
	// Open the games' sockets first so they cannot land inside the pool.
	gameA, gameB, moved := udp(t), udp(t), udp(t)
	defer gameA.Close()
	defer gameB.Close()
	defer moved.Close()
	base := freeBlock(t, 4)
	r := New(j, Options{Latch: true, MinPort: base, MaxPort: base + 3})
	defer r.Close()

	link, err := r.Ensure(1, 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []int{link.PortForA(), link.PortForB()} {
		if p < base || p > base+3 {
			t.Fatalf("relay port %d outside pool %d-%d", p, base, base+3)
		}
	}
	toB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: link.PortForA()}
	toA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: link.PortForB()}

	// A speaks first: B is not known yet, nothing can be delivered.
	_, _ = gameA.WriteToUDP([]byte("early"), toB)
	time.Sleep(30 * time.Millisecond)
	// B speaks: now both are latched, and B's packet reaches A.
	_, _ = gameB.WriteToUDP([]byte("from-b"), toA)
	if got, _, err := read(t, gameA, time.Second); err != nil || got != "from-b" {
		t.Fatalf("A read %q %v", got, err)
	}
	_, _ = gameA.WriteToUDP([]byte("from-a"), toB)
	if got, _, err := read(t, gameB, time.Second); err != nil || got != "from-a" {
		t.Fatalf("B read %q %v", got, err)
	}
	if s := r.Stats()["1->2"]; s.Unlatched != 1 {
		t.Fatalf("expected the early packet to count as unlatched: %+v", s)
	}

	// A's NAT mapping moves: the relay follows it.
	_, _ = moved.WriteToUDP([]byte("moved"), toB)
	if got, _, err := read(t, gameB, time.Second); err != nil || got != "moved" {
		t.Fatalf("B read %q %v", got, err)
	}
	_, _ = gameB.WriteToUDP([]byte("reply"), toA)
	if got, _, err := read(t, moved, time.Second); err != nil || got != "reply" {
		t.Fatalf("moved A read %q %v", got, err)
	}

	// The pool is small; a third link does not fit.
	if _, err = r.Ensure(1, 3, nil, nil); err != nil {
		t.Fatalf("second link should fit in 4 ports: %v", err)
	}
	if _, err = r.Ensure(2, 3, nil, nil); err == nil {
		t.Fatal("pool of 4 ports gave out a third link")
	}
}
