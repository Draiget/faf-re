// Command mpemu-server is the hub of multi-machine runs, and the "remote"
// side of FAF's P2P setup, on one HTTP port:
//
//   - the icebreaker signalling API faf-pioneer's ICE adapter uses;
//   - a STUN/TURN server (relay allocations from a fixed, small port range);
//   - the control channel agents and directors exchange commands over;
//   - a latching UDP relay with impairment for relay-mode runs.
//
// Run it on a LAN machine for LAN tests or on a remote host for internet
// tests, and give machines its DNS name (e.g. faftest.zontwelg.net). Its
// address never needs to appear in any file: -public-host takes the name,
// and MPEMU_PUBLIC_IP can supply the address on the host itself when the
// name resolves differently there.
//
// The secret is read from MPEMU_SECRET or the file named by -secret-file /
// MPEMU_SECRET_FILE, never from the command line. With a secret the API is
// served over TLS under a key derived from it (hub.ServerTLS), so a hub
// known only by an internal DNS name needs no certificate; -tls-cert
// replaces that with a real certificate, -tls off with plain HTTP for a TLS
// proxy in front.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"faf-main/tools/bus"
	"faf-main/tools/hub"
	"faf-main/tools/icebreaker"
	"faf-main/tools/journal"
	"faf-main/tools/turnsrv"
)

func main() {
	var (
		httpAddr    = flag.String("http", "127.0.0.1:8080", "API listen address")
		publicHost  = flag.String("public-host", "", "name machines reach this hub by, e.g. faftest.zontwelg.net")
		turnPort    = flag.Int("turn-port", 3478, "TURN/STUN UDP port (0 disables TURN)")
		turnRange   = flag.String("turn-relay-ports", "", "TURN relay allocation ports, e.g. 40000-40015 (default: any)")
		relayRange  = flag.String("relay-ports", "", "game relay ports, e.g. 40100-40131 (default: any)")
		forceRelay  = flag.Bool("force-relay", false, "tell ICE adapters to use TURN relay candidates only")
		secretFile  = flag.String("secret-file", os.Getenv("MPEMU_SECRET_FILE"), "file holding the shared secret")
		logDir      = flag.String("logs", "mpemu-server-logs", "directory for the journal and uploaded adapter logs")
		verbose     = flag.Bool("v", false, "print every journal record")
		tlsMode     = flag.String("tls", "auto", "auto: TLS keyed from the secret when one is set; off: plain HTTP (behind a TLS proxy)")
		tlsCert     = flag.String("tls-cert", "", "serve TLS with this certificate instead of the secret-derived one")
		tlsKey      = flag.String("tls-key", "", "private key for -tls-cert")
		printTokens = flag.Int("tokens", 0, "print ICE access tokens for users 1..N of -game-id (manual adapter runs)")
		gameID      = flag.Uint64("game-id", 100, "game id for -tokens")
	)
	flag.Parse()

	secret, err := hub.ReadSecret(*secretFile)
	if err != nil {
		fail(err)
	}
	loopback := isLoopback(*httpAddr)
	if secret == "" && !loopback {
		fail(fmt.Errorf("refusing to listen on %s without a secret (MPEMU_SECRET or -secret-file)", *httpAddr))
	}
	turnMin, turnMax, err := portRange(*turnRange)
	if err != nil {
		fail(err)
	}
	relayMin, relayMax, err := portRange(*relayRange)
	if err != nil {
		fail(err)
	}
	if err = os.MkdirAll(*logDir, 0o755); err != nil {
		fail(err)
	}

	var hubSrv *hub.Server
	j, err := journal.New(filepath.Join(*logDir, "journal.jsonl"), func(r journal.Record) {
		if hubSrv != nil {
			hubSrv.Forward(r)
		}
		if *verbose || r.Kind == journal.IceSub || r.Kind == journal.IceUnsub || r.Kind == journal.TurnAlloc ||
			r.Kind == journal.Warn || r.Kind == journal.TurnAuthErr || r.Kind == journal.Note {
			fmt.Printf("%s %-16s g%d u%d %s\n", r.Time.Format("15:04:05.000"), r.Kind, r.Game, r.UID, r.Text)
		}
	})
	if err != nil {
		fail(err)
	}
	defer j.Close()

	var turn *turnsrv.Server
	if *turnPort != 0 {
		turn, err = turnsrv.Start(turnsrv.Config{Port: *turnPort, PublicHost: *publicHost,
			PublicIP: os.Getenv("MPEMU_PUBLIC_IP"), RelayMinPort: turnMin, RelayMaxPort: turnMax, Secret: secret}, j)
		if err != nil {
			fail(err)
		}
		defer turn.Close()
	}

	queue := bus.New()
	ice := icebreaker.New(icebreaker.Options{ForceRelay: *forceRelay, Turn: turn, LogDir: *logDir,
		Secret: secret, Bus: queue}, j)
	hubHost := *publicHost
	if hubHost == "" {
		hubHost, _, _ = net.SplitHostPort(*httpAddr)
	}
	hubSrv = hub.New(hub.Options{Secret: secret, PublicHost: hubHost,
		RelayMinPort: relayMin, RelayMaxPort: relayMax}, j, queue)

	mux := http.NewServeMux()
	ice.Routes(mux)
	hubSrv.Routes(mux)
	ln, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		fail(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	scheme := "https"
	switch {
	case *tlsCert != "" || *tlsKey != "":
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			fail(err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	case *tlsMode == "auto" && secret != "":
		if srv.TLSConfig, err = hub.ServerTLS(secret); err != nil {
			fail(err)
		}
	case *tlsMode == "auto" || *tlsMode == "off":
		scheme = "http"
		if !loopback {
			fmt.Println("WARNING: plain HTTP on a non-loopback address sends the hub secret in clear text;" +
				" only do this behind a TLS proxy")
		}
	default:
		fail(fmt.Errorf("-tls %q: want auto or off", *tlsMode))
	}
	go func() {
		var err error
		if scheme == "https" {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && err != http.ErrServerClosed {
			fail(err)
		}
	}()

	fmt.Printf("mpemu-server listening on %s://%s (public name: %s)\n", scheme, ln.Addr(), orNone(*publicHost))
	if turn != nil {
		fmt.Printf("turn/stun  : %v, relay ports %s\n", turn.URLs(), orAny(*turnRange))
	}
	fmt.Printf("game relay : ports %s\nsecret     : %s\njournal    : %s\n",
		orAny(*relayRange), map[bool]string{true: "set", false: "none (loopback only)"}[secret != ""],
		filepath.Join(*logDir, "journal.jsonl"))
	for uid := 1; uid <= *printTokens; uid++ {
		fmt.Printf("user %d token: %s\n", uid, icebreaker.MintSignedAccessToken(uint(uid), *gameID, secret))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("stopping")
	shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shut)
	_ = srv.Close()
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func portRange(s string) (int, int, error) {
	if s == "" {
		return 0, 0, nil
	}
	lo, hi, ok := strings.Cut(s, "-")
	a, err1 := strconv.Atoi(strings.TrimSpace(lo))
	b, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if !ok || err1 != nil || err2 != nil || a <= 0 || b < a || b > 65535 {
		return 0, 0, fmt.Errorf("port range %q: want MIN-MAX", s)
	}
	return a, b, nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "mpemu-server:", err)
	os.Exit(1)
}
