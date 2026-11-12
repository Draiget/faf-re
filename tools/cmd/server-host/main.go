// Command server-host runs the dedicated server's lobbies on one machine (plan WP17.13). It starts
// with no lobby; each lobby asked for over its REST API runs as its own `server` process, pinned to
// the CPUs chosen for it (or the least loaded ones), and its own REST API is reached through the
// host's. The host reports each CPU's load for a heatmap, the maps it can host and what a game costs.
//
//	server-host --listen 0.0.0.0:27180 --token-file admin.token --server /opt/faf/server \
//	  --maps fa=/data/fa/maps --maps vault=/data/vault/maps --runs /var/faf/lobbies \
//	  --public-host 203.0.113.5 --engine-args "/init /data/faf/bin/init_replay.lua /nobugreport /nosound"
//
// docs/SERVER_DASHBOARD.md describes the API and how to run it with the dashboard.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type mapFlags []mapDir

func (m *mapFlags) String() string { return fmt.Sprint(*m) }
func (m *mapFlags) Set(v string) error {
	label, path, ok := strings.Cut(v, "=")
	if !ok || label == "" || path == "" {
		return errors.New("--maps takes <label>=<folder>, e.g. fa=/data/fa/maps")
	}
	*m = append(*m, mapDir{label, path})
	return nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:27180", "address of the REST API")
	tokenFile := flag.String("token-file", "", "file holding the admin token (required; at least 16 characters)")
	cors := flag.String("cors-origin", "", "a web page's origin allowed to call the API (e.g. http://localhost:5173)")
	serverBin := flag.String("server", "", "the server binary each lobby runs (required)")
	engineArgs := flag.String("engine-args", "", "engine switches every lobby's server gets, e.g. \"/init <init.lua> /nobugreport /nosound\"")
	runs := flag.String("runs", "lobbies", "folder for each lobby's match file, log, replay and result")
	publicHost := flag.String("public-host", "", "address players connect to, for the join command lines (default: the --game-ip, else this machine's outbound address)")
	gameIP := flag.String("game-ip", "0.0.0.0", "address each lobby's server listens on for players")
	ports := flag.String("ports", "27200-27299", "game ports the lobbies take, first-last")
	maxLobbies := flag.Int("max-lobbies", 32, "most lobbies running at once")
	var maps mapFlags
	flag.Var(&maps, "maps", "<label>=<folder> holding map folders; repeat for several (e.g. fa=... vault=...)")
	flag.Parse()

	if *tokenFile == "" || *serverBin == "" || len(maps) == 0 {
		fmt.Fprintln(os.Stderr, "server-host needs --token-file, --server and at least one --maps")
		flag.Usage()
		os.Exit(2)
	}
	tb, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatalf("token file: %v", err)
	}
	token := strings.TrimSpace(string(tb))
	if len(token) < 16 {
		log.Fatalf("the admin token in %s is shorter than 16 characters", *tokenFile)
	}
	if _, err := os.Stat(*serverBin); err != nil {
		log.Fatalf("server binary: %v", err)
	}
	// Each lobby's server runs in its own folder, so a relative --server would name another file there.
	if abs, err := filepath.Abs(*serverBin); err == nil {
		*serverBin = abs
	}
	first, last, ok := strings.Cut(*ports, "-")
	pf, err1 := strconv.Atoi(first)
	pl, err2 := strconv.Atoi(last)
	if !ok || err1 != nil || err2 != nil || pf < 1024 || pl < pf || pl > 65535 {
		log.Fatalf("--ports takes first-last between 1024 and 65535, not %q", *ports)
	}
	if *publicHost == "" {
		*publicHost = *gameIP
		if *publicHost == "0.0.0.0" {
			*publicHost = "127.0.0.1"
			if c, err := net.Dial("udp4", "8.8.8.8:53"); err == nil {
				*publicHost = c.LocalAddr().(*net.UDPAddr).IP.String()
				c.Close()
			}
		}
	}
	if err := os.MkdirAll(*runs, 0o755); err != nil {
		log.Fatalf("runs folder: %v", err)
	}

	smp := newSampler("/proc", "/sys/devices/system/cpu")
	stop := make(chan struct{})
	go smp.run(stop)
	// Plan WP17.16: network links, sampled every second like the CPUs.
	links := &linkSampler{dir: "/sys/class/net"}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			links.sample()
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	}()

	// The map list is read once and again at most every minute.
	var mapsMu sync.Mutex
	var mapsCache []Map
	var mapsAt time.Time
	listMaps := func() []Map {
		mapsMu.Lock()
		defer mapsMu.Unlock()
		if mapsCache == nil || time.Since(mapsAt) > time.Minute {
			mapsCache, mapsAt = scanMaps(maps), time.Now()
		}
		return mapsCache
	}
	log.Printf("maps: %d found in %v", len(listMaps()), maps)

	m := newManager(config{serverBin: *serverBin, engineArgs: strings.Fields(*engineArgs), runsDir: *runs, publicHost: *publicHost,
		listenIP: *gameIP, portFirst: pf, portLast: pl, maxLobbies: *maxLobbies}, listMaps, smp.cpus)
	m.links = links.get
	m.nodes = func() []Node {
		ids := []int{}
		for _, c := range smp.cpus() {
			ids = append(ids, c.ID)
		}
		return readNodes("/sys/devices/system/node", ids)
	}
	a := &api{token: token, corsOrigin: *cors, m: m, maps: listMaps, procDir: "/proc", hostName: hostName()}
	srv := &http.Server{Addr: *listen, Handler: a, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("stopping: every lobby's server first")
		m.stopAll()
		close(stop)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	log.Printf("server-host: REST API on http://%s/api/v1 (no lobby running; players join at %s)", *listen, *publicHost)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
