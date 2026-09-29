// Command mpemu runs Forged Alliance multiplayer sessions against an emulated
// FAF client + lobby server, on one machine or across several through a hub
// (cmd/mpemu-server), with or without the WebRTC ICE adapter (faf-pioneer)
// in between, and checks what happened.
//
//	mpemu run <scenario.yaml> [flags]     run a scenario, exit 0 on PASS
//	mpemu lobby [flags]                   start N instances, host + join, then a console
//	mpemu agent -hub URL [flags]          serve this PC's players for directors elsewhere
//	mpemu selftest [flags]                check the whole stack with fakegame
//	mpemu token -uid 1 [-game-id 100]     print an access token
//
// Hub URL and secret come from -hub / MPEMU_HUB and MPEMU_SECRET /
// -secret-file (MPEMU_SECRET_FILE); secrets are never taken as flags.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"faf-main/tools/agent"
	"faf-main/tools/hub"
	"faf-main/tools/icebreaker"
	"faf-main/tools/launcher"
	"faf-main/tools/procs"
	"faf-main/tools/scenario"
	"faf-main/tools/turnsrv"
)

const usage = `usage:
  mpemu run <scenario.yaml> [-exe game.exe] [-adapter faf-adapter.exe] [-hub URL] [-run-dir dir] [-v]
  mpemu lobby [-n 2] [-mode direct|relay|ice] [-lobby auto|normal] [-map SCMP_009]
              [-exe game.exe] [-no-spawn] [-agents a,b] [-hub URL]
  mpemu agent -hub URL [-name pc2] [-advertise host] [-exe game.exe] [-adapter faf-adapter.exe]
  mpemu selftest [-fakegame fakegame.exe] [-adapter faf-adapter.exe] [-only name] [-remote] [-v]
  mpemu token -uid 1 [-game-id 100]

  hub secret: MPEMU_SECRET, or -secret-file / MPEMU_SECRET_FILE
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var code int
	switch os.Args[1] {
	case "run":
		code = cmdRun(ctx, os.Args[2:])
	case "lobby":
		code = cmdLobby(ctx, os.Args[2:])
	case "agent":
		code = cmdAgent(ctx, os.Args[2:])
	case "selftest":
		code = cmdSelftest(ctx, os.Args[2:])
	case "token":
		code = cmdToken(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", os.Args[1], usage)
		code = 2
	}
	os.Exit(code)
}

// siblingExe finds a tool built next to mpemu.exe (build.ps1 puts them all in bin/).
func siblingExe(name string) string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	p := filepath.Join(filepath.Dir(self), name)
	if _, err = os.Stat(p); err == nil {
		return p
	}
	return ""
}

type common struct {
	runDir, exe, adapter, httpAddr, turnIP string
	hubURL, secretFile, advertise          string
	turnPort                               int
	verbose                                bool
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.runDir, "run-dir", "", "output directory (default runs/<time>-<scenario>)")
	fs.StringVar(&c.exe, "exe", "", "game executable, overrides the scenario (ForgedAlliance.exe or main.exe)")
	fs.StringVar(&c.adapter, "adapter", "", "faf-pioneer faf-adapter.exe for mode ice (default: next to mpemu.exe)")
	fs.StringVar(&c.httpAddr, "http", "", "local icebreaker listen address (default 127.0.0.1:<free>)")
	fs.IntVar(&c.turnPort, "turn-port", 0, "local TURN/STUN UDP port (default 3478)")
	fs.StringVar(&c.turnIP, "turn-ip", "", "address local TURN advertises (default: first private IPv4)")
	fs.StringVar(&c.hubURL, "hub", os.Getenv("MPEMU_HUB"), "hub root URL for multi-machine runs (MPEMU_HUB)")
	fs.StringVar(&c.secretFile, "secret-file", os.Getenv("MPEMU_SECRET_FILE"), "file holding the hub secret")
	fs.StringVar(&c.advertise, "advertise", "", "how other machines reach games on this one (default: first private IPv4)")
	fs.BoolVar(&c.verbose, "v", false, "print every journal record")
}

func (c *common) apply(sc *scenario.Scenario) {
	if c.exe != "" {
		sc.Game.Exe = c.exe
	}
	if c.adapter != "" {
		sc.ICE.Adapter = c.adapter
	}
	if sc.ICE.Adapter == "" {
		sc.ICE.Adapter = siblingExe("faf-adapter.exe")
	}
}

func (c *common) options() (scenario.Options, error) {
	secret, err := hub.ReadSecret(c.secretFile)
	if err != nil {
		return scenario.Options{}, err
	}
	return scenario.Options{RunDir: c.runDir, Verbose: c.verbose, HTTPAddr: c.httpAddr,
		TurnPort: c.turnPort, TurnIP: c.turnIP, Hub: c.hubURL, HubSecret: secret, Advertise: c.advertise}, nil
}

func run(ctx context.Context, sc *scenario.Scenario, opts scenario.Options) int {
	res, err := scenario.Run(ctx, sc, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpemu:", err)
		return 2
	}
	if !res.Pass {
		return 1
	}
	return 0
}

func cmdRun(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var c common
	c.register(fs)
	// Accept flags before or after the scenario path.
	var path string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	if path == "" && fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	if path == "" {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	sc, err := scenario.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpemu:", err)
		return 2
	}
	c.apply(sc)
	opts, err := c.options()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpemu:", err)
		return 2
	}
	return run(ctx, sc, opts)
}

func cmdLobby(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("lobby", flag.ExitOnError)
	var c common
	c.register(fs)
	n := fs.Int("n", 2, "number of players")
	mode := fs.String("mode", "direct", "direct, relay or ice")
	lobby := fs.String("lobby", "auto", "auto (autolobby, launches by itself) or normal (custom game lobby)")
	mapName := fs.String("map", "SCMP_009", "map folder name passed to HostGame")
	noSpawn := fs.Bool("no-spawn", false, "do not start games; print their command lines (debugger)")
	noSound := fs.Bool("nosound", true, "pass /nosound to every instance")
	tile := fs.Bool("tile", true, "pass /position so windows cascade")
	forceRelay := fs.Bool("force-relay", false, "mode ice: TURN relay only")
	agents := fs.String("agents", "", "comma-separated agent per player (empty entries run here), e.g. ,pc2")
	_ = fs.Parse(args)

	spawn := !*noSpawn
	cfg := launcher.Config{
		Mode:  launcher.Mode(*mode),
		Lobby: launcher.LobbyKind(*lobby),
		Map:   *mapName,
		Game:  launcher.GameConfig{NoSound: *noSound, Tile: *tile, Spawn: &spawn},
		ICE:   launcher.ICEConfig{ForceRelay: *forceRelay},
	}
	sc := scenario.Lobby(cfg, *n)
	if *agents != "" {
		for i, name := range strings.Split(*agents, ",") {
			if i < len(sc.Players) {
				sc.Players[i].Agent = strings.TrimSpace(name)
			}
		}
	}
	c.apply(sc)
	opts, err := c.options()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpemu:", err)
		return 2
	}
	return run(ctx, sc, opts)
}

func cmdAgent(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	hubURL := fs.String("hub", os.Getenv("MPEMU_HUB"), "hub root URL (MPEMU_HUB), e.g. https://faftest.zontwelg.net")
	secretFile := fs.String("secret-file", os.Getenv("MPEMU_SECRET_FILE"), "file holding the hub secret")
	host, _ := os.Hostname()
	name := fs.String("name", strings.ToLower(host), "agent name directors address players to")
	advertise := fs.String("advertise", "", "how other machines reach games here (default: first private IPv4)")
	runs := fs.String("runs", filepath.Join("runs", "agent"), "local run directories")
	fafBin := fs.String("fafbin", launcher.DefaultFAFBin(), "this machine's FAF bin folder")
	exe := fs.String("exe", "", "game executable to use for every player here (default: as the director asks)")
	adapter := fs.String("adapter", siblingExe("faf-adapter.exe"), "this machine's faf-adapter.exe (mode ice)")
	_ = fs.Parse(args)

	if *hubURL == "" {
		fmt.Fprintln(os.Stderr, "mpemu agent: -hub (or MPEMU_HUB) is required")
		return 2
	}
	secret, err := hub.ReadSecret(*secretFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpemu agent:", err)
		return 2
	}
	if *advertise == "" {
		*advertise = turnsrv.FirstPrivateIPv4().String()
	}
	err = agent.Run(ctx, agent.Options{Hub: hub.NewClient(*hubURL, secret), Name: *name, Advertise: *advertise,
		RunsDir: *runs, FAFBin: *fafBin, Exe: launcher.ExpandPath(*exe), Adapter: *adapter, Secret: secret})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpemu agent:", err)
		return 1
	}
	return 0
}

func cmdSelftest(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	var c common
	c.register(fs)
	fake := fs.String("fakegame", "", "fakegame executable (default: next to mpemu.exe)")
	only := fs.String("only", "", "run only scenarios whose name contains this")
	remote := fs.Bool("remote", false, "run only the hub selftests, against the hub in -hub / MPEMU_HUB (agents start here)")
	_ = fs.Parse(args)

	if *fake == "" {
		*fake = siblingExe("fakegame.exe")
	}
	if *fake == "" {
		fmt.Fprintln(os.Stderr, "mpemu: fakegame.exe not found next to mpemu.exe; pass -fakegame")
		return 2
	}
	adapter := c.adapter
	if adapter == "" {
		adapter = siblingExe("faf-adapter.exe")
	}
	if adapter == "" {
		fmt.Println("note: faf-adapter.exe not found, skipping the ICE selftests (see build.ps1)")
	}

	root := c.runDir
	if root == "" {
		root = filepath.Join("runs", "selftest-"+time.Now().Format("20060102-150405"))
	}
	failed := 0
	runAll := func(list []*scenario.Scenario, hubURL, secret string) {
		for _, sc := range list {
			if *only != "" && !strings.Contains(sc.Name, *only) {
				continue
			}
			opts := scenario.Options{RunDir: filepath.Join(root, sc.Name), Verbose: c.verbose,
				Hub: hubURL, HubSecret: secret, Advertise: "127.0.0.1"}
			// Selftests are unattended: a console step must only end the way it
			// would with nobody typing, so it gets input that never arrives.
			never, _ := io.Pipe()
			opts.Console = never
			if run(ctx, sc, opts) != 0 {
				failed++
			}
			if ctx.Err() != nil {
				return
			}
		}
	}
	agents := [2]string{"st-a", "st-b"}
	if *remote {
		// A shared hub may serve other people's agents: make these names ours.
		host, _ := os.Hostname()
		agents = [2]string{"st-a-" + strings.ToLower(host), "st-b-" + strings.ToLower(host)}
	} else {
		runAll(scenario.Selftests(*fake, adapter), "", "")
	}

	hubList := scenario.HubSelftests(*fake, adapter, agents, *remote)
	wanted := false
	for _, sc := range hubList {
		wanted = wanted || *only == "" || strings.Contains(sc.Name, *only)
	}
	if wanted && ctx.Err() == nil {
		var stack *hubStack
		var err error
		if *remote {
			stack, err = remoteHub(ctx, filepath.Join(root, "agents"), c.hubURL, c.secretFile, adapter, agents)
		} else {
			stack, err = startLocalHub(ctx, filepath.Join(root, "hub"), adapter, agents)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "mpemu: hub selftests:", err)
			failed++
		} else {
			runAll(hubList, stack.url, stack.secret)
			stack.close()
		}
	}

	if failed > 0 {
		fmt.Printf("\nselftest: %d scenario(s) failed (runs under %s)\n", failed, root)
		return 1
	}
	fmt.Println("\nselftest: all passed")
	return 0
}

// hubStack is the hub the hub selftests run against and the two agent
// processes standing in for test PCs: a local hub (the multi-machine
// topology in miniature) or a deployed one.
type hubStack struct {
	url, secret string
	job         *procs.Job
}

func (h *hubStack) close() { h.job.Close() }

// remoteHub starts this machine's two selftest agents against a deployed hub.
func remoteHub(ctx context.Context, dir, url, secretFile, adapter string, agents [2]string) (*hubStack, error) {
	if url == "" {
		return nil, fmt.Errorf("-remote needs the hub URL in -hub or MPEMU_HUB")
	}
	secret, err := hub.ReadSecret(secretFile)
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, fmt.Errorf("-remote needs the hub secret (MPEMU_SECRET or -secret-file / MPEMU_SECRET_FILE)")
	}
	info, err := hub.NewClient(url, secret).Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("hub %s: %w", url, err)
	}
	job, err := procs.NewJob()
	if err != nil {
		return nil, err
	}
	h := &hubStack{url: url, secret: secret, job: job}
	if err = startAgents(ctx, h, dir, adapter, agents); err != nil {
		job.Close()
		return nil, err
	}
	fmt.Printf("\n== hub %s (public name %s) with agents %v\n", url, info.PublicHost, agents)
	return h, nil
}

func startLocalHub(ctx context.Context, dir, adapter string, agents [2]string) (*hubStack, error) {
	server := siblingExe("mpemu-server.exe")
	if server == "" {
		return nil, fmt.Errorf("mpemu-server.exe not found next to mpemu.exe (run build.ps1)")
	}
	_ = os.MkdirAll(dir, 0o755)
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	secret := hex.EncodeToString(buf)
	env := []string{"MPEMU_SECRET=" + secret}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	httpAddr := ln.Addr().String()
	_ = ln.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	turnPort := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()

	job, err := procs.NewJob()
	if err != nil {
		return nil, err
	}
	// With a secret the hub serves TLS under the secret-derived key, exactly as
	// a deployed hub does; the ICE seats reach it through the gateway.
	h := &hubStack{url: "https://" + httpAddr, secret: secret, job: job}
	if _, err = procs.Start(procs.Spec{Name: "hub", Exe: server, Dir: dir, Env: env,
		Args:   []string{"-http", httpAddr, "-turn-port", strconv.Itoa(turnPort), "-logs", dir},
		Output: filepath.Join(dir, "hub.log")}, job); err != nil {
		job.Close()
		return nil, err
	}
	client := hub.NewClient(h.url, secret)
	if err = waitFor(ctx, 10*time.Second, func() bool { _, e := client.Info(ctx); return e == nil }); err != nil {
		job.Close()
		return nil, fmt.Errorf("local hub did not come up (see %s): %w", filepath.Join(dir, "hub.log"), err)
	}
	if err = startAgents(ctx, h, dir, adapter, agents); err != nil {
		job.Close()
		return nil, err
	}
	fmt.Printf("\n== local hub %s with agents %v\n", h.url, agents)
	return h, nil
}

// startAgents starts the selftest agents in h's job and waits until the hub
// sees them listening.
func startAgents(ctx context.Context, h *hubStack, dir, adapter string, agents [2]string) error {
	self := siblingExe("mpemu.exe")
	if self == "" {
		return fmt.Errorf("mpemu.exe not found (run build.ps1)")
	}
	env := []string{"MPEMU_SECRET=" + h.secret}
	for _, name := range agents {
		agentDir := filepath.Join(dir, name)
		_ = os.MkdirAll(agentDir, 0o755)
		if _, err := procs.Start(procs.Spec{Name: name, Exe: self, Dir: agentDir, Env: env,
			Args: []string{"agent", "-hub", h.url, "-name", name, "-advertise", "127.0.0.1",
				"-runs", agentDir, "-adapter", adapter},
			Output: filepath.Join(agentDir, "agent.log")}, h.job); err != nil {
			return err
		}
	}
	client := hub.NewClient(h.url, h.secret)
	err := waitFor(ctx, 15*time.Second, func() bool {
		listed, e := client.Agents(ctx)
		up := 0
		for _, a := range listed {
			if a.Listening && (a.Name == agents[0] || a.Name == agents[1]) {
				up++
			}
		}
		return e == nil && up == len(agents)
	})
	if err != nil {
		return fmt.Errorf("agents did not connect to the hub (see %s): %w", dir, err)
	}
	return nil
}

func waitFor(ctx context.Context, d time.Duration, ok func() bool) error {
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s", d)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}

func cmdToken(args []string) int {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	uid := fs.Uint("uid", 1, "user id")
	gameID := fs.Uint64("game-id", 100, "game id")
	secretFile := fs.String("secret-file", os.Getenv("MPEMU_SECRET_FILE"), "sign with the hub secret from this file")
	_ = fs.Parse(args)
	secret, err := hub.ReadSecret(*secretFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mpemu token:", err)
		return 2
	}
	fmt.Println(icebreaker.MintSignedAccessToken(*uid, *gameID, secret))
	return 0
}
