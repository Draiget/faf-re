// Command faf-lobby-probe plays FAF players against a FAF lobby stack (faf-message-broker in front of the lobby
// server), the way downlords-faf-client and the game do, without either: each player signs in through an OpenID
// provider (tools/oidcmock's authorization-code flow with PKCE, scope "lobby"), opens the broker's WebSocket, asks for
// a session and authenticates (faf-java-commons FafLobbyClient), and for its game sends the GPGNet messages the game
// would ("target": "game"). It checks what the lobby server answers.
//
// Scenario "pair": player 1 hosts a public game, player 2 joins it. Expected, from FAForever/server
// gameconnection.py: each gets game_launch; after GameState Idle and Lobby the host gets HostGame <map>, the joiner
// gets JoinGame <host login> <host id>, and the host gets ConnectToPeer <joiner login> <joiner id>. With
// -expect-arg, each game_launch's args must also contain that word (a server-hosted game's /connectserver), and no
// player's args may contain another player's -token-arg value.
//
//	faf-lobby-probe -ws ws://broker:8080/ -ws-host localhost -issuer http://oidcmock:4444 -client-id faf-client \
//	    -redirect http://localhost/callback -players 1,2 -map scmp_009
//
// Prints a journal of every message (tokens masked) and one RESULT line; exit 0 when every check passed.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	wsURL     = flag.String("ws", "ws://127.0.0.1:8080/", "the broker's WebSocket URL")
	wsHost    = flag.String("ws-host", "", "Host header for the upgrade (the broker only accepts its allowed hosts)")
	issuer    = flag.String("issuer", "http://127.0.0.1:4444", "the OpenID provider (tools/cmd/oidc-mock)")
	clientID  = flag.String("client-id", "faf-client", "client id registered at the provider")
	redirect  = flag.String("redirect", "http://localhost/callback", "redirect URI registered at the provider")
	players   = flag.String("players", "1,2", "FAF ids of the players: the first hosts, the others join")
	mapName   = flag.String("map", "scmp_009", "map folder name to host")
	mod       = flag.String("mod", "faf", "featured mod to host")
	timeout   = flag.Duration("timeout", 30*time.Second, "how long each expected message may take")
	expectArg = flag.String("expect-arg", "", "a word every game_launch's args must contain (e.g. /connectserver)")
	tokenArg  = flag.String("token-arg", "/servertoken", "the arg whose value must differ per player and never leak")
	control   = flag.String("control", "", "scenario dedicated: the lobby server's control URL (http://host:4000)")
	dedicated = flag.String("dedicated", "", "scenario dedicated: the game server's host:port the game is created for")
	tokensArg = flag.String("tokens", "", "scenario dedicated: id=token,... to use (the game server's), else random")
	seatExe   = flag.String("seat-exe", "", "scenario dedicated: start this per player with --server --uid --token "+
		"taken from its game_launch args (faf_server_probe), plus -seat-args; all must exit 0")
	seatArgs = flag.String("seat-args", "", "scenario dedicated: extra args for -seat-exe, space separated")
)

type player struct {
	id    int
	login string
	ws    *wsConn
	in    chan map[string]any
	token string

	rawMu sync.Mutex
	raw   []string // every line received, for the join-string leak check
}

// received returns every line the player has received so far.
func (p *player) received() []string {
	p.rawMu.Lock()
	defer p.rawMu.Unlock()
	return append([]string(nil), p.raw...)
}

var (
	jmu   sync.Mutex
	start = time.Now()
	fails []string
)

func logf(format string, a ...any) {
	jmu.Lock()
	defer jmu.Unlock()
	fmt.Printf("%7.3f %s\n", time.Since(start).Seconds(), fmt.Sprintf(format, a...))
}

func fail(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	logf("FAIL %s", s)
	jmu.Lock()
	fails = append(fails, s)
	jmu.Unlock()
}

func main() {
	flag.Parse()
	var ids []int
	for _, s := range strings.Split(*players, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			fmt.Fprintln(os.Stderr, "faf-lobby-probe: -players takes FAF ids, e.g. 1,2")
			os.Exit(2)
		}
		ids = append(ids, n)
	}
	if len(ids) < 2 {
		fmt.Fprintln(os.Stderr, "faf-lobby-probe: the pair scenario needs two players")
		os.Exit(2)
	}
	scenario, run := "pair", run
	if *dedicated != "" {
		scenario, run = "dedicated", runDedicated
	}
	ok := run(ids)
	if ok && len(fails) == 0 {
		fmt.Printf("RESULT lobby-probe PASS %s players=%d in %.1fs\n", scenario, len(ids), time.Since(start).Seconds())
		return
	}
	fmt.Printf("RESULT lobby-probe FAIL %d: %s\n", len(fails), strings.Join(fails, "; "))
	os.Exit(1)
}

func run(ids []int) bool {
	var ps []*player
	for _, id := range ids {
		p, err := login(id)
		if err != nil {
			fail("player %d login: %v", id, err)
			return false
		}
		ps = append(ps, p)
		defer p.ws.Close()
	}
	host, joiners := ps[0], ps[1:]

	// Host.
	host.send(map[string]any{"command": "game_host", "visibility": "public", "title": "faf-lobby-probe " +
		time.Now().Format("150405"), "mod": *mod, "mapname": *mapName})
	launch, ok := host.expect("game_launch", nil)
	if !ok {
		return false
	}
	uid := json.Number(fmt.Sprint(launch["uid"]))
	launches := map[int]map[string]any{host.id: launch}
	host.game("GameState", "Idle")
	host.game("GameState", "Lobby")
	if hg, ok := host.expect("HostGame", isGame); ok {
		if a := args(hg); len(a) < 1 || !strings.EqualFold(fmt.Sprint(a[0]), *mapName) {
			fail("host's HostGame args %v, want [%s]", a, *mapName)
		}
	}

	// Joiners, one after another as the lobby server pairs them.
	for _, j := range joiners {
		j.send(map[string]any{"command": "game_join", "uid": uid})
		jl, ok := j.expect("game_launch", nil)
		if !ok {
			return false
		}
		launches[j.id] = jl
		if fmt.Sprint(jl["uid"]) != uid.String() {
			fail("player %d's game_launch uid %v, want %s", j.id, jl["uid"], uid)
		}
		j.game("GameState", "Idle")
		j.game("GameState", "Lobby")
		if jg, ok := j.expect("JoinGame", isGame); ok {
			a := args(jg)
			if len(a) < 2 || fmt.Sprint(a[0]) != host.login || int(num(a[1])) != host.id {
				fail("player %d's JoinGame args %v, want [%s %d]", j.id, a, host.login, host.id)
			}
		}
		if cp, ok := host.expect("ConnectToPeer", isGame); ok {
			a := args(cp)
			if len(a) < 2 || fmt.Sprint(a[0]) != j.login || int(num(a[1])) != j.id {
				fail("host's ConnectToPeer args %v, want [%s %d]", a, j.login, j.id)
			}
		}
	}

	checkLaunchArgs(launches)

	// Leave cleanly: the game ends and closes.
	for _, p := range ps {
		p.game("GameState", "Ended")
	}
	time.Sleep(500 * time.Millisecond)
	return true
}

// runDedicated: the players sign in, the game is created on the lobby server's control endpoint for the game server
// -dedicated with a fresh token per player, and each player must get game_launch with
// "/connectserver <server> /servertoken <own token> /serveruid <own id>", and after GameState Idle and Lobby no peer
// setup (HostGame, JoinGame, ConnectToPeer) at all.
func runDedicated(ids []int) bool {
	var ps []*player
	for _, id := range ids {
		p, err := login(id)
		if err != nil {
			fail("player %d login: %v", id, err)
			return false
		}
		ps = append(ps, p)
		defer p.ws.Close()
	}
	tokens := map[int]string{}
	for _, kv := range strings.Split(*tokensArg, ",") {
		if id, tok, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
			n, _ := strconv.Atoi(id)
			tokens[n] = tok
		}
	}
	var parts []map[string]any
	for i, p := range ps {
		if tokens[p.id] == "" {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			tokens[p.id] = hex.EncodeToString(b)
		}
		parts = append(parts, map[string]any{"player_id": p.id, "token": tokens[p.id], "team": 2 + i%2, "start_spot": i + 1})
	}
	body, _ := json.Marshal(map[string]any{"name": "faf-lobby-probe dedicated", "mapname": *mapName, "mod": *mod,
		"address": *dedicated, "participants": parts})
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Post(strings.TrimRight(*control, "/")+"/dedicated_games",
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		fail("create the game: %v", err)
		return false
	}
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	logf("control <- %s %s", resp.Status, strings.TrimSpace(string(answer)))
	if resp.StatusCode != http.StatusAccepted {
		fail("create the game: %s", resp.Status)
		return false
	}
	launches := map[int]map[string]any{}
	// The first player is launched first (the game's nominal host), the rest once its game reports Lobby.
	for _, p := range ps {
		l, ok := p.expect("game_launch", nil)
		if !ok {
			return false
		}
		launches[p.id] = l
		want := []string{"/connectserver", *dedicated, "/servertoken", tokens[p.id], "/serveruid", strconv.Itoa(p.id)}
		a := args(l)
		got := make([]string, 0, len(want))
		if len(a) >= len(want) {
			for _, v := range a[len(a)-len(want):] {
				got = append(got, fmt.Sprint(v))
			}
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			fail("player %d's game_launch args end %v, want %v", p.id, got, want)
		}
		p.game("GameState", "Idle")
		p.game("GameState", "Lobby")
	}
	*expectArg = "/connectserver"
	checkLaunchArgs(launches)
	// No peer setup may follow.
	quiet := 3 * time.Second
	for _, p := range ps {
		deadline := time.After(quiet)
	wait:
		for {
			select {
			case m, open := <-p.in:
				if !open {
					fail("player %d: connection closed", p.id)
					break wait
				}
				if isGame(m) {
					switch m["command"] {
					case "HostGame", "JoinGame", "ConnectToPeer", "DisconnectFromPeer":
						fail("player %d got %v for a dedicated-server game", p.id, m["command"])
					}
				}
			case <-deadline:
				break wait
			}
		}
	}
	if *seatExe != "" {
		runSeats(launches)
	}
	// A join string reaches its own player in game_launch and nowhere else: not in another player's messages (game
	// lists, game_info, chat), and not in its own player's other messages either.
	for _, p := range ps {
		for _, line := range p.received() {
			for id, tok := range tokens {
				if !strings.Contains(line, tok) {
					continue
				}
				if id != p.id {
					fail("player %d received player %d's token: %.80s", p.id, id, line)
				} else if !strings.Contains(line, `"game_launch"`) {
					fail("player %d's token appeared outside its game_launch: %.80s", p.id, mask(line, tok))
				}
			}
		}
	}
	for _, p := range ps {
		p.game("GameState", "Ended")
	}
	time.Sleep(500 * time.Millisecond)
	return true
}

// runSeats starts -seat-exe for every player with the join string from its own game_launch, as the game would get
// it on its command line, and waits for all of them.
func runSeats(launches map[int]map[string]any) {
	var wg sync.WaitGroup
	for id, l := range launches {
		words := []string{}
		for _, v := range args(l) {
			words = append(words, fmt.Sprint(v))
		}
		value := func(name string) string {
			for i, w := range words {
				if w == name && i+1 < len(words) {
					return words[i+1]
				}
			}
			return ""
		}
		cmdArgs := []string{"--server", value("/connectserver"), "--uid", value("/serveruid"), "--token", value("/servertoken")}
		cmdArgs = append(cmdArgs, strings.Fields(*seatArgs)...)
		wg.Add(1)
		go func(id int, cmdArgs []string) {
			defer wg.Done()
			logf("p%d starts its seat: %s --server %s --uid %s --token <token> %s", id, *seatExe, cmdArgs[1], cmdArgs[3],
				*seatArgs)
			out, err := exec.Command(*seatExe, cmdArgs...).CombinedOutput()
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if len(lines) > 6 {
				lines = lines[len(lines)-6:]
			}
			for _, line := range lines {
				logf("p%d seat | %s", id, line)
			}
			if err != nil {
				fail("player %d's seat (%s): %v", id, *seatExe, err)
			}
		}(id, cmdArgs)
	}
	wg.Wait()
}

// checkLaunchArgs: -expect-arg in every player's args; each player's -token-arg value its own.
func checkLaunchArgs(launches map[int]map[string]any) {
	tokens := map[string]int{}
	for id, l := range launches {
		a := args(l)
		words := make([]string, len(a))
		for i, v := range a {
			words[i] = fmt.Sprint(v)
		}
		if *expectArg != "" && !contains(words, *expectArg) {
			fail("player %d's game_launch args lack %s", id, *expectArg)
		}
		for i, w := range words {
			if w == *tokenArg && i+1 < len(words) {
				if other, dup := tokens[words[i+1]]; dup {
					fail("players %d and %d got the same %s", other, id, *tokenArg)
				}
				tokens[words[i+1]] = id
			}
		}
	}
	for tok, owner := range tokens {
		for id, l := range launches {
			if id != owner && strings.Contains(fmt.Sprint(l), tok) {
				fail("player %d's game_launch carries player %d's %s", id, owner, *tokenArg)
			}
		}
	}
}

func contains(ws []string, w string) bool {
	for _, x := range ws {
		if x == w {
			return true
		}
	}
	return false
}

func isGame(m map[string]any) bool { return m["target"] == "game" }

func args(m map[string]any) []any { a, _ := m["args"].([]any); return a }

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case json.Number:
		f, _ := x.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}

func (p *player) send(m map[string]any) {
	b, _ := json.Marshal(m)
	logf("p%d -> %s", p.id, mask(string(b), p.token))
	if err := p.ws.writeText(append(b, '\n')); err != nil {
		fail("player %d send: %v", p.id, err)
	}
}

// game sends a GPGNet message from the player's game, as the FAF client relays it.
func (p *player) game(cmd string, a ...any) {
	if a == nil {
		a = []any{}
	}
	p.send(map[string]any{"command": cmd, "target": "game", "args": a})
}

// expect waits for the next message with that command (and filter), logging and skipping others.
func (p *player) expect(cmd string, filter func(map[string]any) bool) (map[string]any, bool) {
	deadline := time.After(*timeout)
	for {
		select {
		case m, open := <-p.in:
			if !open {
				fail("player %d: connection closed while waiting for %s", p.id, cmd)
				return nil, false
			}
			if m["command"] == cmd && (filter == nil || filter(m)) {
				return m, true
			}
		case <-deadline:
			fail("player %d: no %s within %s", p.id, cmd, *timeout)
			return nil, false
		}
	}
}

func login(id int) (*player, error) {
	tok, err := accessToken(id)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	ws, err := wsDial(*wsURL, *wsHost, 10*time.Second)
	if err != nil {
		return nil, err
	}
	p := &player{id: id, ws: ws, in: make(chan map[string]any, 256), token: tok}
	go p.readLoop()
	p.send(map[string]any{"command": "ask_session", "version": "faf-lobby-probe", "user_agent": "faf-lobby-probe"})
	s, ok := p.expect("session", nil)
	if !ok {
		return nil, errors.New("no session")
	}
	p.send(map[string]any{"command": "auth", "token": tok, "unique_id": "faf-lobby-probe-" + strconv.Itoa(id),
		"session": s["session"]})
	deadline := time.After(*timeout)
	for {
		select {
		case m, open := <-p.in:
			if !open {
				return nil, errors.New("closed during login")
			}
			switch m["command"] {
			case "welcome":
				if me, _ := m["me"].(map[string]any); me != nil {
					p.login, _ = me["login"].(string)
				}
				if p.login == "" {
					p.login, _ = m["login"].(string)
				}
				logf("p%d signed in as %q", id, p.login)
				return p, nil
			case "authentication_failed", "login_failed":
				return nil, fmt.Errorf("%v", m["text"])
			}
		case <-deadline:
			return nil, errors.New("no welcome")
		}
	}
}

func (p *player) readLoop() {
	defer close(p.in)
	var buf string
	for {
		b, err := p.ws.readMessage()
		if err != nil {
			logf("p%d connection closed: %v", p.id, err)
			return
		}
		buf += string(b)
		for {
			i := strings.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			line := strings.TrimSpace(buf[:i])
			buf = buf[i+1:]
			if line == "" {
				continue
			}
			p.rawMu.Lock()
			p.raw = append(p.raw, line)
			p.rawMu.Unlock()
			// Numbers stay exact: session ids exceed float64's 53 bits.
			var m map[string]any
			dec := json.NewDecoder(strings.NewReader(line))
			dec.UseNumber()
			if err := dec.Decode(&m); err != nil {
				logf("p%d <- unparsed %q", p.id, line)
				continue
			}
			c, _ := m["command"].(string)
			if c == "ping" {
				p.send(map[string]any{"command": "pong", "request_id": m["request_id"]})
				continue
			}
			if c == "game_info" || c == "player_info" || c == "social" || c == "matchmaker_info" {
				logf("p%d <- %s (%d bytes)", p.id, c, len(line))
			} else {
				logf("p%d <- %s", p.id, mask(line, p.token))
			}
			p.in <- m
		}
	}
}

func mask(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "<token>")
}

// accessToken runs the authorization-code flow with PKCE against the provider, signing in as FAF id.
func accessToken(id int) (string, error) {
	verRaw := make([]byte, 32)
	_, _ = rand.Read(verRaw)
	verifier := base64.RawURLEncoding.EncodeToString(verRaw)
	sum := sha256.Sum256([]byte(verifier))
	state := hex.EncodeToString(verRaw[:6])
	q := url.Values{"response_type": {"code"}, "client_id": {*clientID}, "redirect_uri": {*redirect},
		"scope": {"openid offline public_profile lobby"}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"login_as": {strconv.Itoa(id)}}
	c := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(strings.TrimRight(*issuer, "/") + "/oauth2/auth?" + q.Encode())
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		return "", fmt.Errorf("authorize: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {*redirect}, "client_id": {*clientID}, "code_verifier": {verifier}}
	resp, err = c.PostForm(strings.TrimRight(*issuer, "/")+"/oauth2/token", form)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil || t.AccessToken == "" {
		return "", fmt.Errorf("token: %s %v %s", resp.Status, err, t.Error)
	}
	return t.AccessToken, nil
}
