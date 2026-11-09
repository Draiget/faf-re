package seat

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"faf-main/tools/gpgnet"
	"faf-main/tools/journal"
)

// jarBridge stands between a real game and FAF's faf-ice-adapter.jar on a host
// that drops loopback UDP to sockets bound to every interface, where the two
// cannot reach each other: the jar sends the game's datagrams to 127.0.0.1 and
// names its per-peer sockets as 127.0.0.1 (issue #242). It changes nothing the
// jar puts on the wire to its peers.
//
//   - GPGNet goes through it, with the addresses in JoinGame and ConnectToPeer
//     replaced by a socket of its own on `bind`, one per peer.
//   - That socket passes the game's datagrams to the jar's socket for the peer,
//     on `bind`. These are this side's sends, so link steps apply here
//     (contract `shaping: links`), as netlink applies them to its own.
//   - A socket on 127.0.0.1 at the game's lobby port takes what the jar sends
//     the game and passes it on from the peer's socket, the source the game
//     knows the peer by.
type jarBridge struct {
	s       *Seat
	bind    string
	jarPort int
	ln      net.Listener

	mu     sync.Mutex
	lobby  *net.UDPConn         // 127.0.0.1:<lobby port>
	game   *net.UDPAddr         // <bind>:<lobby port>
	peers  map[int]*net.UDPConn // jar's socket port -> the peer's socket on bind
	shaper *linkShaper
}

// startJarBridge listens for the game's GPGNet connection and returns the port
// to give it as /gpgnet.
func (s *Seat) startJarBridge(ctx context.Context, bind string, jarPort int) (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	b := &jarBridge{s: s, bind: bind, jarPort: jarPort, ln: ln, peers: map[int]*net.UDPConn{},
		shaper: newLinkShaper(os.Getenv("FAF_NETLINK_TEST_SHAPING"))}
	s.mu.Lock()
	s.bridge = b
	s.mu.Unlock()
	go b.serve(ctx)
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func (b *jarBridge) warn(format string, args ...any) {
	b.s.emit(journal.Record{Kind: journal.Warn, UID: b.s.cfg.UID, Text: "jar bridge: " + fmt.Sprintf(format, args...)})
}

func (b *jarBridge) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		b.ln.Close()
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.lobby != nil {
			b.lobby.Close()
		}
		for _, c := range b.peers {
			c.Close()
		}
	}()
	// More than one game, if one crashes and is started again.
	for {
		game, err := b.ln.Accept()
		if err != nil {
			return
		}
		b.serveGame(game)
	}
}

func (b *jarBridge) serveGame(game net.Conn) {
	defer game.Close()
	jar, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(b.jarPort))
	if err != nil {
		b.warn("connect to the jar: %v", err)
		return
	}
	defer jar.Close()
	go func() {
		r := bufio.NewReader(game)
		for {
			m, err := gpgnet.ReadMessage(r)
			if err != nil {
				jar.Close()
				return
			}
			if gpgnet.WriteMessage(jar, m) != nil {
				return
			}
		}
	}()
	r := bufio.NewReader(jar)
	for {
		m, err := gpgnet.ReadMessage(r)
		if err != nil {
			return
		}
		if gpgnet.WriteMessage(game, b.rewrite(m)) != nil {
			return
		}
	}
}

// rewrite takes the lobby port from CreateLobby and replaces a peer's address.
func (b *jarBridge) rewrite(m gpgnet.Message) gpgnet.Message {
	switch m.Command {
	case "CreateLobby":
		if port, ok := m.Int(1); ok {
			if err := b.openLobby(int(port)); err != nil {
				b.warn("lobby socket: %v", err)
			}
		}
	case "JoinGame", "ConnectToPeer":
		addr, err := b.peerSocket(m.Str(0))
		if err != nil {
			b.warn("%s %s: %v", m.Command, m.Str(0), err)
			return m
		}
		args := append([]any{addr}, m.Args[1:]...)
		return gpgnet.Message{Command: m.Command, Args: args}
	}
	return m
}

func (b *jarBridge) openLobby(port int) error {
	lobby, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.lobby = lobby
	b.game = &net.UDPAddr{IP: net.ParseIP(b.bind), Port: port}
	b.mu.Unlock()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := lobby.ReadFromUDP(buf)
			if err != nil {
				return
			}
			b.mu.Lock()
			peer, game := b.peers[from.Port], b.game
			b.mu.Unlock()
			if peer != nil {
				_, _ = peer.WriteToUDP(buf[:n], game)
			}
		}
	}()
	return nil
}

// peerSocket opens the socket the game sees a peer at, for the jar's socket
// named by addr ("127.0.0.1:<port>"), and returns the address to give the game.
func (b *jarBridge) peerSocket(addr string) (string, error) {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	jarPort, err := strconv.Atoi(portText)
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if c := b.peers[jarPort]; c != nil {
		return c.LocalAddr().String(), nil
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(b.bind)})
	if err != nil {
		return "", err
	}
	b.peers[jarPort] = c
	to := &net.UDPAddr{IP: net.ParseIP(b.bind), Port: jarPort}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			delay, pass := b.shaper.roll()
			if !pass {
				continue
			}
			if delay <= 0 {
				_, _ = c.WriteToUDP(buf[:n], to)
				continue
			}
			packet := append([]byte(nil), buf[:n]...)
			time.AfterFunc(delay, func() { _, _ = c.WriteToUDP(packet, to) })
		}
	}()
	return c.LocalAddr().String(), nil
}

// linkShaper reads the FAF_NETLINK_TEST_SHAPING file as netlink's TestShaping
// does (src/netlink/Link.cpp): "<latency us> <jitter us> <loss 0-1> <blocked 0|1>",
// at most every 100 ms.
type linkShaper struct {
	path string

	mu       sync.Mutex
	nextRead time.Time
	latency  time.Duration
	jitter   time.Duration
	loss     float64
	blocked  bool
}

func newLinkShaper(path string) *linkShaper { return &linkShaper{path: path} }

// roll says how long a datagram stays in flight, or false when it is lost.
func (l *linkShaper) roll() (time.Duration, bool) {
	if l.path == "" {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.After(l.nextRead) {
		l.nextRead = now.Add(100 * time.Millisecond)
		l.read()
	}
	if l.blocked || (l.loss > 0 && rand.Float64() < l.loss) {
		return 0, false
	}
	delay := l.latency
	if l.jitter > 0 {
		delay += time.Duration(rand.Int63n(int64(l.jitter) + 1))
	}
	return delay, true
}

func (l *linkShaper) read() {
	text, err := os.ReadFile(l.path)
	if err != nil {
		return // keep the last setting
	}
	var latency, jitter int64
	var loss float64
	var blocked int
	if _, err := fmt.Sscan(strings.TrimSpace(string(text)), &latency, &jitter, &loss, &blocked); err != nil {
		return
	}
	l.latency = time.Duration(latency) * time.Microsecond
	l.jitter = time.Duration(jitter) * time.Microsecond
	l.loss = loss
	l.blocked = blocked != 0
}
