package turnsrv

import (
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/turn/v5"

	"faf-main/tools/relay"
)

// impairment is the one setting every shaped socket of a server reads, and the
// relay addresses it has handed out (issue #242).
//
// Each one-way player-to-player path through the server is shaped exactly once,
// at its last hop out of the server:
//   - to a player on a relayed candidate: the client-facing socket's write;
//   - to a player's own address (host or reflexive, which force-relay still
//     uses locally, as FAF's Java adapter does): that relay socket's write.
//
// A relay socket's write to another of this server's relay addresses is left
// alone; the client-facing write after it shapes that path.
type impairment struct {
	imp    atomic.Pointer[relay.Impairment]
	mu     sync.Mutex
	rng    *rand.Rand
	relays sync.Map // relay address string -> struct{}
}

func newImpairment() *impairment {
	i := &impairment{rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
	i.imp.Store(&relay.Impairment{})
	return i
}

func (i *impairment) set(imp relay.Impairment) { i.imp.Store(&imp) }

func (i *impairment) roll() (drop bool, dup bool, delay time.Duration) {
	imp := i.imp.Load()
	if imp.Blocked {
		return true, false, 0
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if imp.Loss > 0 && i.rng.Float64() < imp.Loss {
		return true, false, 0
	}
	delay = imp.Latency
	if imp.Jitter > 0 {
		delay += time.Duration(i.rng.Int63n(int64(imp.Jitter) + 1))
	}
	dup = imp.Duplicate > 0 && i.rng.Float64() < imp.Duplicate
	return false, dup, delay
}

// impairedConn shapes a socket's writes with the server's impairment.
type impairedConn struct {
	net.PacketConn
	shared *impairment
	relay  bool // a relay socket: writes to the server's own relay addresses pass untouched
}

func (c *impairedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.relay {
		if _, own := c.shared.relays.Load(addr.String()); own {
			return c.PacketConn.WriteTo(p, addr)
		}
	}
	drop, dup, delay := c.shared.roll()
	if drop {
		return len(p), nil // lost on the way, as far as the sender can tell
	}
	if delay <= 0 && !dup {
		return c.PacketConn.WriteTo(p, addr)
	}
	b := append([]byte(nil), p...)
	send := func() { _, _ = c.PacketConn.WriteTo(b, addr) }
	if delay <= 0 {
		send()
	} else {
		time.AfterFunc(delay, send)
	}
	if dup {
		time.AfterFunc(delay+time.Millisecond, send)
	}
	return len(p), nil
}

func (c *impairedConn) Close() error {
	if c.relay {
		c.shared.relays.Delete(c.PacketConn.LocalAddr().String())
	}
	return c.PacketConn.Close()
}

// impairedRelays hands out relay sockets that read the server's impairment.
type impairedRelays struct {
	turn.RelayAddressGenerator
	shared *impairment
}

func (g *impairedRelays) AllocatePacketConn(cfg turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	conn, addr, err := g.RelayAddressGenerator.AllocatePacketConn(cfg)
	if err != nil {
		return conn, addr, err
	}
	g.shared.relays.Store(addr.String(), struct{}{})
	g.shared.relays.Store(conn.LocalAddr().String(), struct{}{})
	return &impairedConn{PacketConn: conn, shared: g.shared, relay: true}, addr, nil
}
