// Package turnsrv embeds a STUN/TURN server (Pion TURN) in place of the
// eturnal container faf-icebreaker hands out. Credentials use the same
// time-limited shared-secret scheme ("<expiry>:<user>" / HMAC-SHA1) that
// eturnal and the TURN REST API draft use, so the ICE adapter authenticates
// exactly as it would in production.
package turnsrv

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"faf-main/tools/journal"
)

// Config selects where the server listens and which address it relays from.
type Config struct {
	// ListenIP is the local address to bind; "0.0.0.0" serves every interface.
	ListenIP string
	Port     int
	// PublicHost is what clients are told to contact: the stun:/turn: URLs
	// carry it as given (a DNS name keeps addresses out of configuration).
	PublicHost string
	// PublicIP is the relay address announced in allocations; it must be an
	// address. Empty resolves PublicHost at start-up. A name this host cannot
	// resolve (it exists only in the clients' split-horizon DNS) falls back to
	// the address the host reaches the internet from; no PublicHost picks this
	// machine's first private IPv4, else 127.0.0.1.
	PublicIP string
	// RelayMinPort..RelayMaxPort bound relay allocations (both 0: any port).
	// Behind a firewall that forwards single ports, keep this range small.
	RelayMinPort, RelayMaxPort int
	Realm                      string
	// Secret is the shared secret; empty generates a random one.
	Secret string
}

// Server is a running TURN server.
type Server struct {
	cfg    Config
	server *turn.Server
	ip     net.IP
}

// user is the REST username's user part: "<game>.<uid>".
func user(gameID uint64, uid uint) string { return fmt.Sprintf("%d.%d", gameID, uid) }

func parseUser(userID string) (gameID uint64, uid int) {
	g, u, ok := strings.Cut(userID, ".")
	if !ok {
		u = userID
	}
	gameID, _ = strconv.ParseUint(g, 10, 64)
	uid, _ = strconv.Atoi(u)
	return gameID, uid
}

// Start launches the server. Allocation lifecycle is written to j.
func Start(cfg Config, j *journal.Journal) (*Server, error) {
	if cfg.Port == 0 {
		cfg.Port = 3478
	}
	if cfg.ListenIP == "" {
		cfg.ListenIP = "0.0.0.0"
	}
	if cfg.Realm == "" {
		cfg.Realm = "mpemu.local"
	}
	if cfg.Secret == "" {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		cfg.Secret = hex.EncodeToString(buf)
	}
	ip := net.ParseIP(cfg.PublicIP)
	if ip == nil && cfg.PublicHost != "" {
		addrs, err := net.LookupIP(cfg.PublicHost)
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil {
				ip = v4
				break
			}
		}
		if ip == nil {
			if ip = outboundIPv4(); ip == nil {
				return nil, fmt.Errorf("turn: public host %q does not resolve here (%v) and no outbound address;"+
					" set MPEMU_PUBLIC_IP", cfg.PublicHost, err)
			}
			j.Note(journal.Note, 0, fmt.Sprintf("turn: %s does not resolve on this host; announcing the outbound address",
				cfg.PublicHost), nil)
		}
	}
	if ip == nil {
		ip = firstPrivateIPv4()
	}

	conn, err := net.ListenPacket("udp4", fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("turn listen: %w", err)
	}

	loggers := logging.NewDefaultLoggerFactory()
	loggers.DefaultLogLevel = logging.LogLevelWarn

	var relays turn.RelayAddressGenerator = &turn.RelayAddressGeneratorStatic{RelayAddress: ip, Address: cfg.ListenIP}
	if cfg.RelayMinPort > 0 && cfg.RelayMaxPort >= cfg.RelayMinPort {
		relays = &turn.RelayAddressGeneratorPortRange{RelayAddress: ip, Address: cfg.ListenIP,
			MinPort: uint16(cfg.RelayMinPort), MaxPort: uint16(cfg.RelayMaxPort)}
	}

	rec := func(kind, userID string, data map[string]any) {
		game, uid := parseUser(userID)
		j.Add(journal.Record{Kind: kind, Game: game, UID: uid, Data: data})
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm:             cfg.Realm,
		LoggerFactory:     loggers,
		AuthHandler:       turn.LongTermTURNRESTAuthHandler(cfg.Secret, loggers.NewLogger("turn-auth")),
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: conn, RelayAddressGenerator: relays}},
		EventHandler: turn.EventHandler{
			OnAuth: func(src, _ net.Addr, _, username, _, method string, verdict bool) {
				if !verdict {
					j.Add(journal.Record{Kind: journal.TurnAuthErr, Text: method,
						Data: map[string]any{"from": src.String(), "username": username}})
				}
			},
			OnAllocationCreated: func(src, _ net.Addr, _, userID, _ string, relay net.Addr, _ int) {
				rec(journal.TurnAlloc, userID, map[string]any{"from": src.String(), "relay": relay.String()})
			},
			OnAllocationDeleted: func(src, _ net.Addr, _, userID, _ string) {
				rec(journal.TurnDealloc, userID, map[string]any{"from": src.String()})
			},
			OnAllocationError: func(src, _ net.Addr, _, message string) {
				j.Add(journal.Record{Kind: journal.Warn, Text: "turn allocation error: " + message,
					Data: map[string]any{"from": src.String()}})
			},
			OnPermissionCreated: func(_, _ net.Addr, _, userID, _ string, relay net.Addr, peer net.IP) {
				rec(journal.TurnPerm, userID, map[string]any{"relay": relay.String(), "peer": peer.String()})
			},
			OnChannelCreated: func(_, _ net.Addr, _, userID, _ string, relay, peer net.Addr, ch uint16) {
				rec(journal.TurnChannel, userID, map[string]any{"relay": relay.String(), "peer": peer.String(), "channel": ch})
			},
		},
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("turn server: %w", err)
	}
	return &Server{cfg: cfg, server: server, ip: ip}, nil
}

// URLs are the ICE server URLs to hand to clients.
func (s *Server) URLs() []string {
	host := s.cfg.PublicHost
	if host == "" {
		host = s.ip.String()
	}
	hp := net.JoinHostPort(host, strconv.Itoa(s.cfg.Port))
	return []string{"turn:" + hp + "?transport=udp", "stun:" + hp}
}

// Credentials mints REST credentials for one player of one game, valid for ttl.
func (s *Server) Credentials(gameID uint64, uid uint, ttl time.Duration) (username, password string) {
	username, password, _ = turn.GenerateLongTermTURNRESTCredentials(s.cfg.Secret, user(gameID, uid), ttl)
	return username, password
}

// Allocations is the number of live relay allocations.
func (s *Server) Allocations() int { return s.server.AllocationCount() }

// Addr is the advertised host:port.
func (s *Server) Addr() string {
	host := s.cfg.PublicHost
	if host == "" {
		host = s.ip.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(s.cfg.Port))
}

// Close stops the server.
func (s *Server) Close() error { return s.server.Close() }

func firstPrivateIPv4() net.IP {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if v4 := ipn.IP.To4(); v4 != nil && v4.IsPrivate() {
						return v4
					}
				}
			}
		}
	}
	return net.IPv4(127, 0, 0, 1)
}

// FirstPrivateIPv4 is this machine's first private IPv4 address (LAN address
// used as a default advertisement), or 127.0.0.1.
func FirstPrivateIPv4() net.IP { return firstPrivateIPv4() }

// outboundIPv4 is the source address of this machine's default route.
// Connecting a UDP socket only selects the route; nothing is sent to the
// documentation address used as the destination.
func outboundIPv4() net.IP {
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return nil
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok && !a.IP.IsUnspecified() {
		return a.IP.To4()
	}
	return nil
}
