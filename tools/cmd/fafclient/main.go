// Command fafclient runs one emulated FAF game: N players, each with an ICE
// adapter started exactly as downlords-faf-client starts it, and a game
// connected to that adapter over GPGNet. It plays the lobby server's part
// (HostGame, JoinGame, ConnectToPeer, IceMsg relay) and records every RPC
// frame in a JSONL trace.
//
//	fafclient -players 2 -native-dir tmp/claude/net-layers/ref [-java <java.exe>] [-exe <adapter.exe>]
//	          [-turn] [-force-relay] [-game fake | -game-cmd "<exe> /gpgnet {gpgnet} ..."]
//	          [-hold 30s] [-trace out.jsonl] [-logs dir]
//
// With -game fake each player's game is tools/fakegame in this process. The
// run passes when every game reports GameState Launching (all its peers
// answer UDP pings through the adapters) and, after -hold, no ping was lost.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"faf-main/tools/fafclient"
	"faf-main/tools/fakegame"
	"faf-main/tools/journal"
	"faf-main/tools/procs"
	"faf-main/tools/turnsrv"
)

func main() {
	players := flag.Int("players", 2, "number of players (player 1 hosts)")
	nativeDir := flag.String("native-dir", "", "folder with faf-ice-adapter.jar (the client's nativeDir)")
	java := flag.String("java", `C:\Program Files\FAF Client\jre\bin\java.exe`, "java executable; empty with -exe runs a native adapter")
	exe := flag.String("exe", "", `native adapter executable (instead of the jar), comma-separated per player to mix ("jar" keeps the jar for that player)`)
	exeArgs := flag.String("exe-args", "", "extra arguments for native adapters only, after the launcher's (e.g. --bind-address 192.168.42.77)")
	clientLib := flag.String("client-lib", `C:\Program Files\FAF Client\lib`, "the client's lib folder; its javafx-* jars go on the class path, as the client adds them (read only)")
	forceRelay := flag.Bool("force-relay", false, "pass --force-relay to every adapter")
	useTurn := flag.Bool("turn", true, "start a local STUN/TURN server and hand it out with setIceServers")
	turnPort := flag.Int("turn-port", 3478, "TURN/STUN port")
	turnIP := flag.String("turn-ip", outboundIPv4(), "address the TURN server binds and relays from (default: the address of the outbound route; a TURN server on 127.0.0.1 got no allocations from the Java adapter on the test machine)")
	gameBind := flag.String("game-bind", "", "address the fake game binds its lobby port to (default every interface, as the game; 127.0.0.1 where inbound UDP to 0.0.0.0 is blocked)")
	game := flag.String("game", "fake", `"fake" runs tools/fakegame in-process`)
	gameCmd := flag.String("game-cmd", "", `game command line, {gpgnet} and {login} are replaced`)
	mode := flag.String("init-mode", "normal", "setLobbyInitMode argument (normal or auto)")
	loadTime := flag.Duration("load-time", 2*time.Second, "fake game loading time before GameState Idle (the real game takes seconds; FAF's adapter 3.3.14 can lose a game that reports Idle within ms of connecting)")
	hold := flag.Duration("hold", 20*time.Second, "how long to keep the game running after every game launched")
	timeout := flag.Duration("timeout", 90*time.Second, "time allowed until every game launched")
	tracePath := flag.String("trace", "", "JSONL trace of every RPC frame and lobby step")
	logDir := flag.String("logs", "", "LOG_DIR root for the adapters (one subfolder per player)")
	quiet := flag.Bool("q", false, "don't echo the trace")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	j, err := journal.New(*tracePath, func(r journal.Record) {
		if !*quiet {
			fmt.Printf("%s %-14s uid=%d %s %s\n", r.Time.Format("15:04:05.000"), r.Kind, r.UID, r.Command, clip(r.Text, 300))
		}
	})
	if err != nil {
		fail(err)
	}
	defer j.Close()

	const gameID = 1001
	ps := make([]fafclient.Player, *players)
	for i := range ps {
		ps[i] = fafclient.Player{ID: 101 + i, Login: fmt.Sprintf("player%d", i+1)}
	}

	var iceServers []map[string]any
	if *useTurn {
		ts, err := turnsrv.Start(turnsrv.Config{ListenIP: *turnIP, Port: *turnPort, PublicHost: *turnIP, PublicIP: *turnIP}, j)
		if err != nil {
			fail(err)
		}
		defer ts.Close()
		// The client maps each CoturnServer to {urls, username, credential}
		// (IceServerMapper); one entry for the whole list is enough here. The
		// shipped adapter reads each URL with java.net.URI and needs its host
		// part, so "turn:h:p" (opaque, no host) throws "hostname can't be
		// null"; "turn://h:p" parses.
		var urls []string
		for _, u := range ts.URLs() {
			scheme, rest, _ := strings.Cut(u, ":")
			urls = append(urls, scheme+"://"+rest)
		}
		user, pass := ts.Credentials(gameID, uint(ps[0].ID), time.Hour)
		iceServers = []map[string]any{{"urls": urls, "username": user, "credential": pass}}
	} else {
		iceServers = []map[string]any{}
	}

	// IceAdapterImpl.getJavaFXClassPathJars: every class path entry whose name
	// contains "javafx-" (so javafxsvg-*.jar stays out).
	var fx []string
	if entries, err := os.ReadDir(*clientLib); err == nil {
		for _, e := range entries {
			if strings.Contains(e.Name(), "javafx-") {
				fx = append(fx, filepath.Join(*clientLib, e.Name()))
			}
		}
	}
	javafx := strings.Join(fx, string(os.PathListSeparator))

	exes := strings.Split(*exe, ",")
	adapters := make([]fafclient.Adapter, len(ps))
	for i := range adapters {
		a := fafclient.Adapter{Java: *java, NativeDir: *nativeDir, JavaFXClassPath: javafx, ForceRelay: *forceRelay, LogDir: *logDir}
		if *exe != "" {
			if e := strings.TrimSpace(exes[i%len(exes)]); e != "" && e != "jar" {
				a.Java, a.Exe = "", e
				a.Extra = strings.Fields(*exeArgs)
			}
		}
		adapters[i] = a
	}

	job, err := procs.NewJob()
	if err != nil {
		fail(err)
	}
	defer job.Close()

	var mu sync.Mutex
	states := map[int]string{}
	var gameWG sync.WaitGroup
	start := func(ctx context.Context, p fafclient.Player, gpg string) error {
		if *gameCmd != "" {
			line := strings.NewReplacer("{gpgnet}", gpg, "{login}", p.Login).Replace(*gameCmd)
			f := strings.Fields(line)
			c := exec.CommandContext(ctx, f[0], f[1:]...)
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			j.Add(journal.Record{Kind: journal.ProcStart, UID: p.ID, Text: "game: " + line})
			if err := c.Start(); err != nil {
				return err
			}
			return job.Assign(c.Process.Pid)
		}
		if *game != "fake" {
			return fmt.Errorf("unknown -game %q", *game)
		}
		opts := fakegame.Options{GpgNet: gpg, Players: len(ps), BindIP: *gameBind, LoadTime: *loadTime}
		if *logDir != "" {
			_ = os.MkdirAll(*logDir, 0o755)
			opts.LogPath = fmt.Sprintf("%s/fakegame-%s.log", *logDir, p.Login)
		}
		gameWG.Add(1)
		go func() {
			defer gameWG.Done()
			if err := fakegame.Run(ctx, opts); err != nil {
				j.Note(journal.Warn, p.ID, "fakegame: "+err.Error(), nil)
			}
		}()
		return nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	lobby, err := fafclient.Start(runCtx, fafclient.Options{
		Players: ps, GameID: gameID, Map: "scmp_009", InitMode: *mode, IceServers: iceServers,
		Adapters: adapters, StartGame: start, Journal: j, Job: job,
		Token: "emulator-token", IcebreakerURL: "http://127.0.0.1:1/ice",
	})
	if err != nil {
		fail(err)
	}

	// Wait for every game to report Launching.
	deadline := time.Now().Add(*timeout)
	launched := false
	for time.Now().Before(deadline) && ctx.Err() == nil {
		n := 0
		mu.Lock()
		for _, p := range ps {
			states[p.ID] = lobby.Session(p.ID).GameState()
			if states[p.ID] == "Launching" {
				n++
			}
		}
		mu.Unlock()
		if n == len(ps) {
			launched = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if launched {
		j.Note(journal.Step, 0, fmt.Sprintf("every game launched; holding %s", *hold), nil)
		select {
		case <-ctx.Done():
		case <-time.After(*hold):
		}
	} else {
		j.Note(journal.Verdict, 0, fmt.Sprintf("not every game launched: %v", states), nil)
	}

	stats := lastPeerStats(j)
	lobby.Close()
	cancel()
	gameWG.Wait()

	ok := launched
	fmt.Println("\nplayer  peer  settled  answered  heard  lost  avgRTT(us)")
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := stats[k]
		lost := s[1] - s[2]
		fmt.Printf("%-7d %-5d %-8d %-9d %-6d %-5d %d\n", s[0], s[6], s[1], s[2], s[3], lost, s[4])
		if lost != 0 || s[2] == 0 {
			ok = false
		}
	}
	if len(stats) < len(ps)*(len(ps)-1) {
		ok = false
	}
	if ok {
		fmt.Println("PASS")
		return
	}
	fmt.Println("FAIL")
	os.Exit(1)
}

// lastPeerStats returns, per "uid/peer", the newest PeerStats a fake game sent
// through its adapter: [uid, settled, answered, heard, avgRtt, maxRtt, peer].
func lastPeerStats(j *journal.Journal) map[string][7]int {
	out := map[string][7]int{}
	for _, r := range j.Query(func(r journal.Record) bool {
		return r.Kind == fafclient.RPCIn && strings.Contains(r.Text, `"PeerStats"`)
	}) {
		var m fafclient.Message
		if json.Unmarshal([]byte(r.Text), &m) != nil || len(m.Params) < 2 {
			continue
		}
		var args []int
		if json.Unmarshal(m.Params[1], &args) != nil || len(args) < 5 {
			continue
		}
		out[fmt.Sprintf("%05d/%05d", r.UID, args[0])] = [7]int{r.UID, args[1], args[2], args[3], args[4], 0, args[0]}
	}
	return out
}

// outboundIPv4 is the local address of the default route (no packet is sent).
// The first private address can belong to an interface the adapters' STUN and
// TURN requests never reach, which stalls candidate gathering.
func outboundIPv4() string {
	c, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "fafclient:", err)
	os.Exit(2)
}
