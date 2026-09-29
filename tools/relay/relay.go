// Package relay routes game-to-game UDP through mpemu so links can be
// impaired: latency, jitter, loss, duplication, and full partitions.
//
// Each pair of players {A, B} gets two sockets. A is told (JoinGame /
// ConnectToPeer) that B lives at sockB, and B that A lives at sockA. A packet
// A sends to sockB is forwarded out of sockA to B's game, so B sees it arrive
// from the address it was told belongs to A, and the reverse for B. This is
// the per-peer port topology the ICE adapter presents to the game, without
// WebRTC in between.
//
// On one machine each game's address is known up front. On a hub reached
// over the internet it is not (the games sit behind NAT), so a latching relay
// learns each game's public address from the first packet it sends, the way
// a TURN relay does, and binds its sockets from a fixed port pool that a
// firewall can forward one port at a time.
package relay

import (
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"faf-main/tools/journal"
)

// Impairment shapes one direction of a link.
type Impairment struct {
	Latency   time.Duration `json:"latency" yaml:"latency"`
	Jitter    time.Duration `json:"jitter" yaml:"jitter"`
	Loss      float64       `json:"loss" yaml:"loss"`           // 0..1
	Duplicate float64       `json:"duplicate" yaml:"duplicate"` // 0..1
	Blocked   bool          `json:"blocked" yaml:"blocked"`
}

func (i Impairment) active() bool {
	return i.Latency > 0 || i.Jitter > 0 || i.Loss > 0 || i.Duplicate > 0 || i.Blocked
}

// DirStats counts one direction of a link.
type DirStats struct {
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	Dropped   uint64 `json:"dropped"`
	Blocked   uint64 `json:"blocked"`
	Duplicate uint64 `json:"duplicated"`
	Stray     uint64 `json:"stray"`     // fixed mode: from an unexpected address
	Unlatched uint64 `json:"unlatched"` // latch mode: the far side has not sent yet
	Relatched uint64 `json:"relatched"` // latch mode: the sender's address changed (NAT rebinding)
}

type direction struct {
	mu    sync.Mutex
	imp   Impairment
	stats struct {
		packets, bytes, dropped, blocked, duplicated, stray, unlatched, relatched atomic.Uint64
	}
}

func (d *direction) snapshot() DirStats {
	return DirStats{
		Packets: d.stats.packets.Load(), Bytes: d.stats.bytes.Load(), Dropped: d.stats.dropped.Load(),
		Blocked: d.stats.blocked.Load(), Duplicate: d.stats.duplicated.Load(), Stray: d.stats.stray.Load(),
		Unlatched: d.stats.unlatched.Load(), Relatched: d.stats.relatched.Load(),
	}
}

// Link is one proxied pair. A < B.
type Link struct {
	A, B int
	// sockA represents A to B (B sends here); sockB represents B to A.
	sockA, sockB *net.UDPConn
	// gameA / gameB: where each game is. Fixed up front, or learned (latch).
	gameA, gameB atomic.Pointer[net.UDPAddr]
	latch        bool
	ab, ba       direction
	closed       atomic.Bool
}

// Options configure a relay.
type Options struct {
	// Default impairment applied both ways to new links.
	Default Impairment
	// ListenIP binds the link sockets; nil means 127.0.0.1.
	ListenIP net.IP
	// MinPort..MaxPort is the port pool for link sockets (0: any free port).
	MinPort, MaxPort int
	// Latch learns each game's address from its first packet instead of
	// requiring it up front (games behind NAT, relay on a remote hub).
	Latch bool
}

// Relay owns every link of a run.
type Relay struct {
	j       *journal.Journal
	opts    Options
	mu      sync.Mutex
	links   map[[2]int]*Link
	stop    chan struct{}
	stopped sync.Once
}

// New creates a relay.
func New(j *journal.Journal, opts Options) *Relay {
	if opts.ListenIP == nil {
		opts.ListenIP = net.IPv4(127, 0, 0, 1)
	}
	r := &Relay{j: j, opts: opts, links: make(map[[2]int]*Link), stop: make(chan struct{})}
	go r.reportLoop()
	return r
}

func order(a, b int) (int, int) {
	if a < b {
		return a, b
	}
	return b, a
}

// usedPorts lists the ports this relay holds (pool bookkeeping).
func (r *Relay) usedPortsLocked() map[int]bool {
	used := map[int]bool{}
	for _, l := range r.links {
		used[l.sockA.LocalAddr().(*net.UDPAddr).Port] = true
		used[l.sockB.LocalAddr().(*net.UDPAddr).Port] = true
	}
	return used
}

// listenLocked binds one link socket, from the pool when there is one.
// taken is a socket already picked for the link being built.
func (r *Relay) listenLocked(taken *net.UDPConn) (*net.UDPConn, error) {
	if r.opts.MinPort <= 0 {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: r.opts.ListenIP})
	}
	used := r.usedPortsLocked()
	if taken != nil {
		used[taken.LocalAddr().(*net.UDPAddr).Port] = true
	}
	for port := r.opts.MinPort; port <= r.opts.MaxPort; port++ {
		if used[port] {
			continue
		}
		if c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: r.opts.ListenIP, Port: port}); err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("relay: port pool %d-%d exhausted", r.opts.MinPort, r.opts.MaxPort)
}

// Ensure creates the link between a and b. gameA / gameB are the games'
// addresses; in latch mode they may be nil and are learned from traffic.
func (r *Relay) Ensure(a, b int, gameA, gameB *net.UDPAddr) (*Link, error) {
	if a == b {
		return nil, fmt.Errorf("relay: link to self (%d)", a)
	}
	if a > b {
		a, b, gameA, gameB = b, a, gameB, gameA
	}
	if !r.opts.Latch && (gameA == nil || gameB == nil) {
		return nil, fmt.Errorf("relay: link %d<->%d needs both game addresses", a, b)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if l := r.links[[2]int{a, b}]; l != nil {
		return l, nil
	}
	sockA, err := r.listenLocked(nil)
	if err != nil {
		return nil, err
	}
	sockB, err := r.listenLocked(sockA)
	if err != nil {
		_ = sockA.Close()
		return nil, err
	}
	l := &Link{A: a, B: b, sockA: sockA, sockB: sockB, latch: r.opts.Latch}
	r.links[[2]int{a, b}] = l
	l.gameA.Store(gameA)
	l.gameB.Store(gameB)
	l.ab.imp, l.ba.imp = r.opts.Default, r.opts.Default
	// A sends to sockB; forward out of sockA towards B.
	go l.pump(l.sockB, &l.gameA, l.sockA, &l.gameB, &l.ab)
	// B sends to sockA; forward out of sockB towards A.
	go l.pump(l.sockA, &l.gameB, l.sockB, &l.gameA, &l.ba)
	data := map[string]any{"portForA": l.PortForA(), "portForB": l.PortForB(), "latch": l.latch}
	if gameA != nil && gameB != nil {
		data["gameA"], data["gameB"] = gameA.String(), gameB.String()
	}
	r.j.Add(journal.Record{Kind: journal.RelayLink, UID: a, Peer: b, Text: "created", Data: data})
	return l, nil
}

// PortForA is the relay port A must send to in order to reach B.
func (l *Link) PortForA() int { return l.sockB.LocalAddr().(*net.UDPAddr).Port }

// PortForB is the relay port B must send to in order to reach A.
func (l *Link) PortForB() int { return l.sockA.LocalAddr().(*net.UDPAddr).Port }

// Port is the relay port viewer sends to in order to reach target.
func (r *Relay) Port(viewer, target int) (int, error) {
	a, b := order(viewer, target)
	r.mu.Lock()
	l := r.links[[2]int{a, b}]
	r.mu.Unlock()
	if l == nil {
		return 0, fmt.Errorf("relay: no link %d<->%d", viewer, target)
	}
	if viewer == l.A {
		return l.PortForA(), nil
	}
	return l.PortForB(), nil
}

// AddrFor is the local address viewer must use to reach target.
func (r *Relay) AddrFor(viewer, target int) (string, error) {
	port, err := r.Port(viewer, target)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(r.opts.ListenIP.String(), fmt.Sprint(port)), nil
}

// Set applies imp to traffic from -> to (both ways when both is set).
func (r *Relay) Set(from, to int, imp Impairment, both bool) error {
	a, b := order(from, to)
	r.mu.Lock()
	l := r.links[[2]int{a, b}]
	r.mu.Unlock()
	if l == nil {
		return fmt.Errorf("relay: no link %d<->%d", from, to)
	}
	apply := func(d *direction) { d.mu.Lock(); d.imp = imp; d.mu.Unlock() }
	if both {
		apply(&l.ab)
		apply(&l.ba)
	} else if from == l.A {
		apply(&l.ab)
	} else {
		apply(&l.ba)
	}
	r.j.Add(journal.Record{Kind: journal.RelayLink, UID: from, Peer: to, Text: "impairment",
		Data: map[string]any{"both": both, "impairment": imp}})
	return nil
}

// Isolate blocks (or unblocks) every link touching uid.
func (r *Relay) Isolate(uid int, blocked bool) {
	r.mu.Lock()
	var touched []*Link
	for k, l := range r.links {
		if k[0] == uid || k[1] == uid {
			touched = append(touched, l)
		}
	}
	r.mu.Unlock()
	for _, l := range touched {
		for _, d := range []*direction{&l.ab, &l.ba} {
			d.mu.Lock()
			d.imp.Blocked = blocked
			d.mu.Unlock()
		}
	}
	r.j.Add(journal.Record{Kind: journal.RelayLink, UID: uid, Text: "isolate",
		Data: map[string]any{"blocked": blocked, "links": len(touched)}})
}

// Stats returns per-link counters keyed "A->B".
func (r *Relay) Stats() map[string]DirStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]DirStats, 2*len(r.links))
	for _, l := range r.links {
		out[fmt.Sprintf("%d->%d", l.A, l.B)] = l.ab.snapshot()
		out[fmt.Sprintf("%d->%d", l.B, l.A)] = l.ba.snapshot()
	}
	return out
}

// Close tears every link down and journals the final counters.
func (r *Relay) Close() {
	r.stopped.Do(func() {
		close(r.stop)
		r.j.Add(journal.Record{Kind: journal.RelayStats, Text: "final", Data: r.Stats()})
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, l := range r.links {
			l.closed.Store(true)
			_ = l.sockA.Close()
			_ = l.sockB.Close()
		}
	})
}

func (r *Relay) reportLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			r.mu.Lock()
			n := len(r.links)
			r.mu.Unlock()
			if n > 0 {
				r.j.Add(journal.Record{Kind: journal.RelayStats, Data: r.Stats()})
			}
		}
	}
}

// pump reads what the sender's game sends to `in`, and forwards it out of
// `out` to the receiving game.
func (l *Link) pump(in *net.UDPConn, sender *atomic.Pointer[net.UDPAddr], out *net.UDPConn,
	dst *atomic.Pointer[net.UDPAddr], d *direction) {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := in.ReadFromUDP(buf)
		if err != nil {
			if l.closed.Load() {
				return
			}
			// Typically WSAECONNRESET: an ICMP port-unreachable from a game
			// that exited. The socket stays usable; back off so a repeating
			// error cannot spin a core.
			time.Sleep(5 * time.Millisecond)
			continue
		}
		known := sender.Load()
		switch {
		case known == nil && l.latch:
			sender.Store(from)
		case known != nil && (from.Port != known.Port || !from.IP.Equal(known.IP)):
			if !l.latch {
				d.stats.stray.Add(1)
				continue
			}
			sender.Store(from) // the NAT mapping moved
			d.stats.relatched.Add(1)
		}
		d.stats.packets.Add(1)
		d.stats.bytes.Add(uint64(n))
		target := dst.Load()
		if target == nil {
			d.stats.unlatched.Add(1) // the far side has not sent anything yet
			continue
		}

		d.mu.Lock()
		imp := d.imp
		d.mu.Unlock()

		if !imp.active() {
			_, _ = out.WriteToUDP(buf[:n], target)
			continue
		}
		if imp.Blocked {
			d.stats.blocked.Add(1)
			continue
		}
		if imp.Loss > 0 && rand.Float64() < imp.Loss {
			d.stats.dropped.Add(1)
			continue
		}
		copies := 1
		if imp.Duplicate > 0 && rand.Float64() < imp.Duplicate {
			copies = 2
			d.stats.duplicated.Add(1)
		}
		pkt := append([]byte(nil), buf[:n]...)
		for c := 0; c < copies; c++ {
			delay := imp.Latency
			if imp.Jitter > 0 {
				delay += time.Duration(rand.Int64N(int64(2*imp.Jitter))) - imp.Jitter
			}
			if delay <= 0 {
				_, _ = out.WriteToUDP(pkt, target)
				continue
			}
			time.AfterFunc(delay, func() {
				if !l.closed.Load() {
					_, _ = out.WriteToUDP(pkt, target)
				}
			})
		}
	}
}
