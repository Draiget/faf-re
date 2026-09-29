// Package fakegame is a stand-in for the game process: it takes the game's
// command line (/gpgnet, /players, /log), speaks GPGNet the way
// moho::CGpgNetInterface does, and exchanges numbered UDP pings with every
// peer it is told about. It reports what it measures back over GPGNet as
// "PeerStats" messages, and "GameState Launching" once it hears everyone, as
// autolobby would. Scenarios run against it to validate the network stack
// (direct, relay with impairment, ICE through faf-pioneer) without a game.
package fakegame

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"faf-main/tools/gpgnet"
)

// Options mirror the game's command line.
type Options struct {
	GpgNet  string // /gpgnet host:port
	Players int    // /players N (0: launch once every announced peer answers)
	LogPath string // /log path
	// PingInterval between UDP pings to each peer.
	PingInterval time.Duration
	// StatsInterval between PeerStats reports.
	StatsInterval time.Duration
	// ExitAfter quits this long after launching (/exitafter 3s), as a player
	// closing the game would. Zero runs until killed.
	ExitAfter time.Duration
	// LoadTime is how long the game takes to load before it reports Idle
	// (/loadtime 4s). The real game needs seconds, and the ICE adapter
	// normally finishes connecting peers within them: JoinGame and
	// ConnectToPeer only follow Idle. Zero reports Idle at once.
	LoadTime time.Duration
}

// ParseArgs reads the options out of a game-style command line.
func ParseArgs(args []string) Options {
	o := Options{PingInterval: 100 * time.Millisecond, StatsInterval: 2 * time.Second}
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch strings.ToLower(args[i]) {
		case "/gpgnet":
			o.GpgNet = next()
		case "/players":
			o.Players, _ = strconv.Atoi(next())
		case "/log":
			o.LogPath = next()
		case "/exitafter":
			o.ExitAfter, _ = time.ParseDuration(next())
		case "/loadtime":
			o.LoadTime, _ = time.ParseDuration(next())
		}
	}
	return o
}

// lossGrace is how long an unanswered ping may be in flight before it counts
// as lost; pings younger than this are left out of every report.
const lossGrace = time.Second

type peer struct {
	uid      int
	name     string
	addr     *net.UDPAddr
	sent     uint64
	inflight map[uint64]time.Time // seq -> sent at, until answered or lost
	lost     uint64               // unanswered after the link came up
	prelink  uint64               // sent before the first answer (link setup)
	up       bool
	heard    uint64 // pings received from the peer
	acked    uint64 // our pings the peer answered (duplicates ignored)
	rttSum   time.Duration
	rttMax   time.Duration
	sendErr  bool // a send to this peer has failed (logged once)
}

type game struct {
	opts   Options
	log    *log.Logger
	quit   context.CancelFunc
	connMu sync.Mutex
	conn   net.Conn

	mu       sync.Mutex
	uid      int
	name     string
	udp      *net.UDPConn
	peers    map[int]*peer
	launched bool
}

// Run plays one game until ctx ends or the GPGNet connection closes.
func Run(ctx context.Context, opts Options) error {
	if opts.GpgNet == "" {
		return errors.New("fakegame: /gpgnet host:port is required")
	}
	if opts.PingInterval <= 0 {
		opts.PingInterval = 100 * time.Millisecond
	}
	if opts.StatsInterval <= 0 {
		opts.StatsInterval = 2 * time.Second
	}
	var out io.Writer = os.Stderr
	if opts.LogPath != "" {
		if f, err := os.Create(opts.LogPath); err == nil {
			defer f.Close()
			out = f
		}
	}
	g := &game{opts: opts, log: log.New(out, "fakegame ", log.Ltime|log.Lmicroseconds), peers: map[int]*peer{}}

	var conn net.Conn
	var err error
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err = net.DialTimeout("tcp", opts.GpgNet, 2*time.Second)
		if err == nil || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("fakegame: connect %s: %w", opts.GpgNet, err)
	}
	g.conn = conn
	defer conn.Close()
	defer g.closeUDP()
	g.log.Printf("connected to GPGNet %s", opts.GpgNet)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g.quit = cancel
	go func() { <-ctx.Done(); _ = conn.Close() }()

	if opts.LoadTime > 0 {
		g.log.Printf("loading for %s (/loadtime)", opts.LoadTime)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.LoadTime):
		}
	}
	g.send(gpgnet.New("GameState", "Idle"))
	go g.pingLoop(ctx)
	go g.statsLoop(ctx)

	r := bufio.NewReader(conn)
	for {
		m, err := gpgnet.ReadMessage(r)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		g.log.Printf("<- %s", m)
		g.handle(ctx, m)
	}
}

func (g *game) send(m gpgnet.Message) {
	g.connMu.Lock()
	defer g.connMu.Unlock()
	if err := gpgnet.WriteMessage(g.conn, m); err != nil {
		g.log.Printf("send %s: %v", m.Command, err)
		return
	}
	g.log.Printf("-> %s", m)
}

func (g *game) handle(ctx context.Context, m gpgnet.Message) {
	switch m.Command {
	case "CreateLobby":
		port, _ := m.Int(1)
		uid, _ := m.Int(3)
		// Every interface, as the game binds its lobby port: peers can be on
		// other machines or behind a hub's relay on the internet.
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(port)})
		if err != nil {
			g.log.Printf("CreateLobby: bind udp %d: %v", port, err)
			return
		}
		g.mu.Lock()
		g.uid, g.name, g.udp = int(uid), m.Str(2), udp
		g.mu.Unlock()
		g.log.Printf("lobby on %s as %s (%d)", udp.LocalAddr(), m.Str(2), uid)
		go g.readLoop(ctx, udp)
		g.send(gpgnet.New("GameState", "Lobby"))
	case "HostGame":
		g.log.Printf("hosting %s", m.Str(0))
	case "JoinGame", "ConnectToPeer":
		uid, _ := m.Int(2)
		addr, err := net.ResolveUDPAddr("udp4", m.Str(0))
		if err != nil {
			g.log.Printf("%s: bad address %q: %v", m.Command, m.Str(0), err)
			return
		}
		g.mu.Lock()
		g.peers[int(uid)] = &peer{uid: int(uid), name: m.Str(1), addr: addr, inflight: map[uint64]time.Time{}}
		g.mu.Unlock()
	case "DisconnectFromPeer":
		uid, _ := m.Int(0)
		g.mu.Lock()
		delete(g.peers, int(uid))
		g.mu.Unlock()
		g.send(gpgnet.New("Disconnected", strconv.Itoa(int(uid))))
	}
}

// Packet formats: "P <from> <seq> <nanos>" ping, "A <from> <seq> <nanos>" answer.
func (g *game) pingLoop(ctx context.Context) {
	t := time.NewTicker(g.opts.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		g.mu.Lock()
		udp, uid := g.udp, g.uid
		for _, p := range g.peers {
			if udp == nil {
				break
			}
			p.sent++
			now := time.Now()
			p.inflight[p.sent] = now
			msg := fmt.Sprintf("P %d %d %d", uid, p.sent, now.UnixNano())
			if _, err := udp.WriteToUDP([]byte(msg), p.addr); err != nil && !p.sendErr {
				p.sendErr = true
				g.log.Printf("ping to %d at %s: %v", p.uid, p.addr, err)
			}
		}
		g.mu.Unlock()
	}
}

func (g *game) readLoop(ctx context.Context, udp *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(5 * time.Millisecond) // WSAECONNRESET from a peer that went away
			continue
		}
		f := strings.Fields(string(buf[:n]))
		if len(f) != 4 {
			continue
		}
		sender, _ := strconv.Atoi(f[1])
		sentAt, _ := strconv.ParseInt(f[3], 10, 64)
		g.mu.Lock()
		p := g.peers[sender]
		switch f[0] {
		case "P":
			if p != nil {
				p.heard++
			}
			reply := fmt.Sprintf("A %d %s %s", g.uid, f[2], f[3])
			_, _ = udp.WriteToUDP([]byte(reply), from)
		case "A":
			seq, _ := strconv.ParseUint(f[2], 10, 64)
			if p != nil {
				if _, ok := p.inflight[seq]; ok { // a duplicated answer counts once
					delete(p.inflight, seq)
					if !p.up {
						// First answer: the link is up. Whatever older is still
						// unanswered was sent during setup (e.g. before an ICE
						// adapter's data channel opened), not lost on a live link.
						p.up = true
						for older := range p.inflight {
							if older < seq {
								delete(p.inflight, older)
								p.prelink++
							}
						}
					}
					rtt := time.Duration(time.Now().UnixNano() - sentAt)
					p.acked++
					p.rttSum += rtt
					if rtt > p.rttMax {
						p.rttMax = rtt
					}
				}
			}
		}
		launch := g.readyLocked()
		g.mu.Unlock()
		if launch {
			g.send(gpgnet.New("GameState", "Launching"))
			if g.opts.ExitAfter > 0 {
				g.log.Printf("will quit in %s (/exitafter)", g.opts.ExitAfter)
				time.AfterFunc(g.opts.ExitAfter, g.quit)
			}
		}
	}
}

// readyLocked reports (once) that every expected peer is answering pings.
func (g *game) readyLocked() bool {
	if g.launched {
		return false
	}
	want := g.opts.Players - 1
	if want <= 0 {
		want = len(g.peers)
	}
	if want <= 0 || len(g.peers) < want {
		return false
	}
	for _, p := range g.peers {
		if p.acked == 0 || p.heard == 0 {
			return false
		}
	}
	g.launched = true
	return true
}

func (g *game) statsLoop(ctx context.Context) {
	t := time.NewTicker(g.opts.StatsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		g.mu.Lock()
		var reports []gpgnet.Message
		now := time.Now()
		for _, p := range g.peers {
			for seq, at := range p.inflight {
				if now.Sub(at) > lossGrace {
					delete(p.inflight, seq)
					if p.up {
						p.lost++
					} else {
						p.prelink++
					}
				}
			}
			avg := time.Duration(0)
			if p.acked > 0 {
				avg = p.rttSum / time.Duration(p.acked)
			}
			// PeerStats peer settled answered heard avgRttMicros maxRttMicros prelink
			// settled = answered + lost: pings sent on the live link and no
			// longer in flight. prelink = pings that went unanswered before
			// the link first carried an answer.
			reports = append(reports, gpgnet.New("PeerStats", p.uid, int(p.acked+p.lost), int(p.acked),
				int(p.heard), int(avg/time.Microsecond), int(p.rttMax/time.Microsecond), int(p.prelink)))
		}
		g.mu.Unlock()
		for _, m := range reports {
			g.send(m)
		}
	}
}

func (g *game) closeUDP() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.udp != nil {
		_ = g.udp.Close()
	}
}
