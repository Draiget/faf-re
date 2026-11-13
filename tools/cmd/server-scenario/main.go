// Command server-scenario runs one dedicated-server scenario (plan WP16.4): a server game with remote seats played by
// faf_server_probe and the rest by AIs, a timeline of seats leaving and coming back, then checks on what each part
// reported and a headless playback of the server's replay. The server is Linux-only, so this runs on Linux, next to
// a build of server, headless and faf_server_probe:
//
//	GOOS=linux go build -o server-scenario ./cmd/server-scenario
//	server-scenario --build <dir with server, headless, faf_server_probe> --data <game data, as server --data>
//	    --out <dir> [--sync-policy <file>] [--no-spy] scenarios/server/server-1v1.yaml
//
// The playback runs the spy client too (headless --view-bench --lua-routing --spy): every Lua Sync key and id each
// player's client would get in that game is checked against its audience, and one outside it, a renumbered id sent
// raw, a view that doesn't decode or a fan-out guard flag fails the scenario. --sync-policy gives the server and the
// spy a routing policy file (tools/sync-routing/policy_gen.py) in place of the compiled table.
//
// The scenario files are tools/scenarios/server/*.yaml (a folder of their own: mpemu loads tools/scenarios/*.yaml) (format below, in Scenario). Exit code 0 when every check
// passed, 1 when one failed, 2 for bad input.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// Scenario is one tools/scenarios/server/*.yaml file.
type Scenario struct {
	Kind        string `yaml:"kind"` // "server"
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Map is the scenario file the match plays; it needs a start spot for every seat and AI.
	Map  string `yaml:"map"`
	Seed int    `yaml:"seed"`
	// Seats are the remote players, each a faf_server_probe of its own, in start-spot order before the AIs.
	Seats []Seat `yaml:"seats"`
	AIs   []AI   `yaml:"ais"`
	// Server: extra server flags, and when it stops (--stop-beat; 0 runs to the end of the game or the timeout).
	Server struct {
		Args        []string `yaml:"args"`
		StopBeat    int      `yaml:"stopBeat"`
		JoinSeconds int      `yaml:"joinSeconds"`
	} `yaml:"server"`
	Steps   []Step        `yaml:"steps"`
	Timeout time.Duration `yaml:"timeout"`
	Expect  Expect        `yaml:"expect"`
}

// Seat is one remote player.
type Seat struct {
	UID  int      `yaml:"uid"`
	Team int      `yaml:"team"`
	Args []string `yaml:"args"` // extra faf_server_probe flags: orders, impairments (--latency-ms, --loss, ...)
	// Late seats start only with a "start" step.
	Late bool `yaml:"late"`
}

// AI is one army the server's sim plays itself.
type AI struct {
	Team        int    `yaml:"team"`
	Personality string `yaml:"personality"` // default "adaptive"
}

// Step happens At after the server started: a seat's process killed (a crash: no leave message), or a seat started
// again with the same token (a reconnect).
type Step struct {
	At    time.Duration `yaml:"at"`
	Kill  int           `yaml:"kill"`
	Start int           `yaml:"start"`
	Args  []string      `yaml:"args"` // with start: flags for this run of the seat, in place of the seat's own
}

// Expect is what passes.
type Expect struct {
	ServerExit *int `yaml:"serverExit"` // default 0
	// Clean: every seat run that was not killed exits 0 (joined, saw beats, every view decoded) and reports
	// "(0 didn't match)" for its frame checks.
	Clean bool `yaml:"clean"`
	// Playback: headless plays the server's replay and every recorded checksum matches.
	Playback bool `yaml:"playback"`
	// Present: substrings the server's console output must have, Absent: must not.
	Present []string `yaml:"present"`
	Absent  []string `yaml:"absent"`
}

type seatRun struct {
	uid    int
	n      int
	cmd    *exec.Cmd
	out    string
	killed bool
	done   chan struct{}
	code   int
}

var (
	checksRe   = regexp.MustCompile(`(\d+) checks \((\d+) didn't match\)`)
	viewsRe    = regexp.MustCompile(`(\d+) views, (\d+) didn't decode`)
	verdictRe  = regexp.MustCompile(`VERDICT ended=(\w+) mismatches=(\d+) crash=(\w+)`)
	beatsRe    = regexp.MustCompile(`beats=(\d+)`)
	// headless --spy's line (src/headless/ReplaySyncSpy.cpp).
	spyRe = regexp.MustCompile(`lua spy: (\d+) keys over (\d+) view beats, \d+ ids \(\d+ in marked fields\); ` +
		`(\d+) keys with no route, (\d+) outside their audience, (\d+) renumbered ids sent raw, (\d+) that did not ` +
		`decode; (\d+) unmarked ids of other armies; (\d+) writes of unrouted keys, (\d+) fan-out guard flags`)
	failures   []string
	failuresMu sync.Mutex
)

func fail(format string, args ...any) {
	failuresMu.Lock()
	defer failuresMu.Unlock()
	failures = append(failures, fmt.Sprintf(format, args...))
}

func token(uid int) string { return fmt.Sprintf("token-of-seat-%d-not-in-replay", uid) }

// matchFile is the server's --match file for the scenario: the seats as humans owned by their uids, the AIs, in
// start-spot order, each on its team.
func matchFile(s *Scenario) string {
	var b strings.Builder
	fmt.Fprintf(&b, "-- Written by tools/cmd/server-scenario for %s.\nMatchSeed = %d\nMatchTokens = {", s.Name, s.Seed)
	for _, seat := range s.Seats {
		fmt.Fprintf(&b, " ['%d'] = '%s',", seat.UID, token(seat.UID))
	}
	b.WriteString(" }\nMatchConfig = {\n  GameMods = {},\n  Observers = {},\n  GameOptions = {\n")
	fmt.Fprintf(&b, "    ScenarioFile = '%s',\n", s.Map)
	for _, kv := range [][2]string{{"Victory", "demoralization"}, {"Share", "FullShare"}, {"UnitCap", "1000"},
		{"GameSpeed", "normal"}, {"FogOfWar", "explored"}, {"CheatsEnabled", "false"}, {"CivilianAlliance", "enemy"},
		{"Timeouts", "3"}, {"NoRushOption", "Off"}, {"PrebuiltUnits", "Off"}, {"RevealCivilians", "Yes"},
		{"TeamSpawn", "fixed"}, {"TeamLock", "locked"}, {"Score", "no"}} {
		fmt.Fprintf(&b, "    %s = '%s',\n", kv[0], kv[1])
	}
	b.WriteString("    AllowObservers = true,\n  },\n  PlayerOptions = {\n")
	spot := 0
	player := func(fields string, team int) {
		spot++
		fmt.Fprintf(&b, "    [%d] = {\n      %s Civilian = false,\n      Faction = %d, Team = %d, StartSpot = %d, Ready = true, "+
			"MEAN = 1500, DEV = 500, PL = 1000,\n      NG = 100, DIV = '', Country = '', Clan = '', BadMap = false, "+
			"PlayerColor = %d, ArmyColor = %d,\n    },\n", spot, fields, 1+(spot-1)%4, team, spot, spot, spot)
	}
	for _, seat := range s.Seats {
		player(fmt.Sprintf("PlayerName = 'Seat %d', Human = true, OwnerID = '%d',", seat.UID, seat.UID), seat.Team)
	}
	for i, ai := range s.AIs {
		personality := ai.Personality
		if personality == "" {
			personality = "adaptive"
		}
		player(fmt.Sprintf("PlayerName = 'AI %d', Human = false, AIPersonality = '%s',", i+1, personality), ai.Team)
	}
	b.WriteString("  },\n}\n")
	return b.String()
}

func main() {
	build := flag.String("build", "", "folder with server, headless and faf_server_probe")
	data := flag.String("data", "", "game data folder (server --data; headless uses <data>/faf/bin/init_replay.lua)")
	outDir := flag.String("out", "", "output folder (made empty first)")
	port := flag.Int("port", 27100, "the server's UDP port on 127.0.0.1")
	syncPolicy := flag.String("sync-policy", "", "a Lua Sync routing policy file for the server and the spy "+
		"(tools/sync-routing/policy_gen.py); default the compiled table")
	noSpy := flag.Bool("no-spy", false, "play the replay back without the spy")
	flag.Parse()
	if flag.NArg() != 1 || *build == "" || *data == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "usage: server-scenario --build <dir> --data <dir> --out <dir> [--port n] "+
			"[--sync-policy <file>] [--no-spy] <scenario.yaml>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var s Scenario
	if err := yaml.Unmarshal(raw, &s); err != nil || s.Kind != "server" || s.Map == "" || len(s.Seats) == 0 {
		fmt.Fprintf(os.Stderr, "%s: not a server scenario (kind: server, a map and at least one seat): %v\n", flag.Arg(0), err)
		os.Exit(2)
	}
	if s.Timeout == 0 {
		s.Timeout = 20 * time.Minute
	}
	if s.Seed == 0 {
		s.Seed = 12345
	}
	_ = os.RemoveAll(*outDir)
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	matchPath := filepath.Join(*outDir, "match.lua")
	if err := os.WriteFile(matchPath, []byte(matchFile(&s)), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("== %s: %d seats, %d AIs on %s\n", s.Name, len(s.Seats), len(s.AIs), s.Map)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	join := s.Server.JoinSeconds
	if join == 0 {
		join = 30
	}
	args := []string{"--match", matchPath, "--out", filepath.Join(*outDir, "game"), "--data", *data, "--listen", addr,
		"--join-seconds", strconv.Itoa(join), "--timeout", fmt.Sprintf("%.1f", s.Timeout.Minutes()), "/nobugreport",
		"/nosound", "--status-minutes", "0.25"}
	if s.Server.StopBeat > 0 {
		args = append(args, "--stop-beat", strconv.Itoa(s.Server.StopBeat))
	}
	if *syncPolicy != "" {
		args = append(args, "--sync-policy", *syncPolicy)
	}
	args = append(args, s.Server.Args...)
	serverOut := filepath.Join(*outDir, "server.out")
	server, serverDone, err := start(filepath.Join(*build, "server"), args, serverOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
	t0 := time.Now()
	time.Sleep(time.Second)

	var runs []*seatRun
	byUID := map[int]*seatRun{}
	launch := func(seat Seat, extra []string) {
		n := 1
		if prev := byUID[seat.UID]; prev != nil {
			n = prev.n + 1
		}
		probeArgs := []string{"--server", addr, "--uid", strconv.Itoa(seat.UID), "--token", token(seat.UID),
			"--seconds", fmt.Sprintf("%.0f", s.Timeout.Seconds())}
		if extra != nil {
			probeArgs = append(probeArgs, extra...)
		} else {
			probeArgs = append(probeArgs, seat.Args...)
		}
		out := filepath.Join(*outDir, fmt.Sprintf("seat-%d.%d.out", seat.UID, n))
		cmd, done, err := start(filepath.Join(*build, "faf_server_probe"), probeArgs, out)
		if err != nil {
			fail("seat %d: %v", seat.UID, err)
			return
		}
		r := &seatRun{uid: seat.UID, n: n, cmd: cmd, out: out, done: make(chan struct{})}
		go func() { r.code = <-done; close(r.done) }()
		runs = append(runs, r)
		byUID[seat.UID] = r
		fmt.Printf("%6.1f s: seat %d run %d started\n", time.Since(t0).Seconds(), seat.UID, n)
	}
	seats := map[int]Seat{}
	for _, seat := range s.Seats {
		seats[seat.UID] = seat
		if !seat.Late {
			launch(seat, nil)
		}
	}
	for _, step := range s.Steps {
		if wait := step.At - time.Since(t0); wait > 0 {
			select {
			case <-time.After(wait):
			case code := <-serverDone:
				serverDone <- code // the game ended before the step: keep the code for below
				fail("the server ended before the step at %s", step.At)
			}
		}
		switch {
		case step.Kill != 0:
			if r := byUID[step.Kill]; r != nil && r.cmd.Process != nil {
				r.killed = true
				_ = r.cmd.Process.Signal(syscall.SIGKILL)
				fmt.Printf("%6.1f s: seat %d killed\n", time.Since(t0).Seconds(), step.Kill)
			}
		case step.Start != 0:
			seat, ok := seats[step.Start]
			if !ok {
				fail("step at %s starts seat %d, which is not in seats", step.At, step.Start)
				continue
			}
			launch(seat, step.Args)
		}
	}
	serverCode := <-serverDone
	fmt.Printf("%6.1f s: server exited %d\n", time.Since(t0).Seconds(), serverCode)
	for _, r := range runs {
		select {
		case <-r.done:
		case <-time.After(15 * time.Second):
			_ = r.cmd.Process.Signal(syscall.SIGTERM)
			<-r.done
		}
	}
	_ = server

	// Checks.
	want := 0
	if s.Expect.ServerExit != nil {
		want = *s.Expect.ServerExit
	}
	if serverCode != want {
		fail("server exit code %d, expected %d", serverCode, want)
	}
	console, _ := os.ReadFile(serverOut)
	for _, text := range s.Expect.Present {
		if !strings.Contains(string(console), text) {
			fail("server output lacks %q", text)
		}
	}
	for _, text := range s.Expect.Absent {
		if strings.Contains(string(console), text) {
			fail("server output has %q", text)
		}
	}
	for _, r := range runs {
		body, _ := os.ReadFile(r.out)
		views, checks := lastMatch(viewsRe, body), lastMatch(checksRe, body)
		summary := fmt.Sprintf("seat %d run %d: exit %d", r.uid, r.n, r.code)
		if views != nil {
			summary += fmt.Sprintf(", %s views (%s didn't decode)", views[1], views[2])
		}
		if checks != nil {
			summary += fmt.Sprintf(", %s checks (%s didn't match)", checks[1], checks[2])
		}
		if r.killed {
			summary += ", killed"
		}
		fmt.Println(summary)
		if !s.Expect.Clean || r.killed {
			continue
		}
		if r.code != 0 {
			fail("seat %d run %d exited %d", r.uid, r.n, r.code)
		}
		if checks == nil || checks[2] != "0" {
			fail("seat %d run %d: frame checks not all matched", r.uid, r.n)
		}
	}
	if s.Expect.Playback {
		replay := filepath.Join(*outDir, "game", "game.scfareplay")
		playOut := filepath.Join(*outDir, "playback.out")
		playArgs := []string{"--label", "playback", "--replay", replay,
			"/init", filepath.Join(*data, "faf", "bin", "init_replay.lua"), "/nobugreport", "/nosound",
			"/log", filepath.Join(*outDir, "playback.log"), "--timeout", "30"}
		if !*noSpy {
			// The spy client (plan WP16.3) in every scenario game: the same game's views built again with the Lua
			// routing, and every Lua key and id each player's client would receive checked against its audience.
			playArgs = append(playArgs, "--view-bench", filepath.Join(*outDir, "playback.bench"), "--lua-routing", "--spy")
			if *syncPolicy != "" {
				playArgs = append(playArgs, "--sync-policy", *syncPolicy)
			}
		}
		_, done, err := start(filepath.Join(*build, "headless"), playArgs, playOut)
		if err != nil {
			fail("playback: %v", err)
		} else {
			<-done
			body, _ := os.ReadFile(playOut)
			v := lastMatch(verdictRe, body)
			beats := lastMatch(beatsRe, body)
			switch {
			case v == nil:
				fail("playback: no verdict")
			case v[2] != "0" || v[3] != "False":
				fail("playback: mismatches=%s crash=%s", v[2], v[3])
			default:
				b := "?"
				if beats != nil {
					b = beats[1]
				}
				fmt.Printf("playback: %s beats, mismatches 0\n", b)
			}
			if !*noSpy {
				spy := lastMatch(spyRe, body)
				switch {
				case spy == nil:
					fail("spy: no summary line")
				case spy[4] != "0" || spy[5] != "0" || spy[6] != "0" || spy[9] != "0":
					fail("spy: %s outside their audience, %s renumbered ids sent raw, %s didn't decode, %s fan-out "+
						"guard flags", spy[4], spy[5], spy[6], spy[9])
				default:
					// Keys with no route reach observers only (never a leak); unmarked ids are reported for a look.
					fmt.Printf("spy: %s keys over %s view beats, 0 outside their audience, 0 sent raw, 0 undecoded, "+
						"0 guard flags; %s keys with no route (%s writes, observers only), %s unmarked ids of other "+
						"armies\n", spy[1], spy[2], spy[3], spy[8], spy[7])
				}
			}
		}
	}
	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Println("FAIL", f)
		}
		fmt.Printf("RESULT %s FAILED (%d)\n", s.Name, len(failures))
		os.Exit(1)
	}
	fmt.Printf("RESULT %s PASSED\n", s.Name)
}

// start runs a command with its output in a file; the channel gets its exit code (-1 when it couldn't be read).
func start(path string, args []string, out string) (*exec.Cmd, chan int, error) {
	f, err := os.Create(out)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(path, args...)
	w := bufio.NewWriter(f)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, nil, err
	}
	done := make(chan int, 1)
	go func() {
		err := cmd.Wait()
		_ = w.Flush()
		f.Close()
		code := 0
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else if err != nil {
			code = -1
		}
		done <- code
	}()
	return cmd, done, nil
}

func lastMatch(re *regexp.Regexp, body []byte) []string {
	all := re.FindAllStringSubmatch(string(body), -1)
	if len(all) == 0 {
		return nil
	}
	return all[len(all)-1]
}
