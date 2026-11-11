package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Seat is one seat of a lobby, as asked for and as reported.
type Seat struct {
	Seat    int    `json:"seat"`
	Kind    string `json:"kind"` // human, ai
	Name    string `json:"name"`
	UID     int    `json:"uid,omitempty"`
	AI      string `json:"ai,omitempty"`
	Faction int    `json:"faction"`
	Team    int    `json:"team"`
	Join    string `json:"join,omitempty"`
	token   string
}

// LobbyMap is the part of a map a lobby reports.
type LobbyMap struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	KM      int    `json:"km"`
	Players int    `json:"players"`
}

// Lobby is one lobby: its own server process.
type Lobby struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	State          string            `json:"state"` // starting, lobby, game, ended, failed, stopped
	Map            LobbyMap          `json:"map"`
	Options        map[string]string `json:"options"`
	CPUs           []int             `json:"cpus"`
	CPUsAllowed    string            `json:"cpus_allowed,omitempty"`
	Port           int               `json:"port"`
	PID            int               `json:"pid"`
	Created        string            `json:"created"`
	Control        string            `json:"control"`
	StartWhenReady float64           `json:"start_when_ready"`
	Seats          []Seat            `json:"seats"`
	Hint           Hint              `json:"hint"`
	Phase          string            `json:"phase"`
	Beat           int               `json:"beat"`
	Exit           string            `json:"exit"`
	Dir            string            `json:"dir"`

	restPort  int
	restToken string
	proc      *os.Process
	stopAsked bool
	done      chan struct{}
}

// CreateRequest is POST /api/v1/lobbies's body.
type CreateRequest struct {
	Name           string            `json:"name"`
	Map            string            `json:"map"`
	Options        map[string]string `json:"options"`
	Seats          []Seat            `json:"seats"`
	Control        string            `json:"control"`
	StartWhenReady float64           `json:"start_when_ready"`
	LobbyMinutes   float64           `json:"lobby_minutes"`
	CPUs           json.RawMessage   `json:"cpus"` // [ids] or "auto"
	Cores          int               `json:"cores"`
}

// config is how the host starts each lobby's server.
type config struct {
	serverBin  string
	engineArgs []string
	runsDir    string
	publicHost string
	listenIP   string
	portFirst  int
	portLast   int
	maxLobbies int
}

type manager struct {
	cfg     config
	mu      sync.Mutex
	lobbies map[string]*Lobby
	next    int
	maps    func() []Map
	cpus    func() []CPU
	client  *http.Client
}

func newManager(cfg config, maps func() []Map, cpus func() []CPU) *manager {
	return &manager{cfg: cfg, lobbies: map[string]*Lobby{}, next: 1, maps: maps, cpus: cpus, client: &http.Client{Timeout: 3 * time.Second}}
}

var (
	reOptionKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	aiKeys      = []string{"easy", "medium", "adaptive", "rush", "turtle", "tech", "random", "adaptivecheat", "rushcheat", "turtlecheat", "techcheat", "randomcheat"}
	// Options the host sets itself; a request can't change them.
	fixedOptions = map[string]bool{"ScenarioFile": true, "TeamLock": true}
)

func defaultOptions() map[string]string {
	return map[string]string{
		"Victory": "demoralization", "Share": "FullShare", "UnitCap": "1000", "GameSpeed": "normal",
		"FogOfWar": "explored", "CheatsEnabled": "false", "CivilianAlliance": "enemy", "Timeouts": "3",
		"NoRushOption": "Off", "PrebuiltUnits": "Off", "RevealCivilians": "Yes", "TeamSpawn": "fixed", "Score": "no",
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomInt(n int) int {
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}

// luaString quotes s for Lua, escaping what a single-quoted string can't hold.
func luaString(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch {
		case r == '\\' || r == '\'':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\%d`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// validate checks a request against the map and fills the seats in: kinds, names, uids, tokens,
// random factions resolved (the launch takes 1..4 only).
func (m *manager) validate(req *CreateRequest) (Map, error) {
	var mp Map
	found := false
	for _, x := range m.maps() {
		if x.ID == strings.ToLower(req.Map) {
			mp, found = x, true
			break
		}
	}
	if !found {
		return mp, fmt.Errorf("no map %q in the host's map folders", req.Map)
	}
	if len(req.Seats) == 0 {
		return mp, errors.New("a lobby needs at least one seat")
	}
	if len(req.Seats) > mp.Players {
		return mp, fmt.Errorf("%s has %d start spots, not %d", mp.Name, mp.Players, len(req.Seats))
	}
	switch req.Control {
	case "":
		req.Control = "player"
	case "player", "organiser":
	default:
		return mp, errors.New(`control is "player" or "organiser"`)
	}
	if req.StartWhenReady < 0 || req.StartWhenReady > 3600 {
		return mp, errors.New("start_when_ready is 0..3600 seconds")
	}
	if req.LobbyMinutes == 0 {
		req.LobbyMinutes = 60
	}
	if req.LobbyMinutes < 1 || req.LobbyMinutes > 24*60 {
		return mp, errors.New("lobby_minutes is 1..1440")
	}
	for k, v := range req.Options {
		if !reOptionKey.MatchString(k) || fixedOptions[k] {
			return mp, fmt.Errorf("game option %q can't be set", k)
		}
		if len(v) > 64 || strings.ContainsAny(v, "\n\r") {
			return mp, fmt.Errorf("game option %s: value too long or not one line", k)
		}
	}
	humans := 0
	uids := map[int]bool{}
	nextUID := 1001
	for i := range req.Seats {
		s := &req.Seats[i]
		s.Seat = i + 1
		if len(s.Name) > 40 {
			return mp, fmt.Errorf("seat %d: name too long", s.Seat)
		}
		if s.Faction == 0 || s.Faction == 5 {
			s.Faction = 1 + randomInt(4)
		}
		if s.Faction < 1 || s.Faction > 4 {
			return mp, fmt.Errorf("seat %d: faction is 1..5", s.Seat)
		}
		if s.Team == 0 {
			s.Team = 1
		}
		if s.Team < 1 || s.Team > 9 {
			return mp, fmt.Errorf("seat %d: team is 1 (none) or 2..9", s.Seat)
		}
		switch s.Kind {
		case "human":
			humans++
			if s.UID == 0 {
				for uids[nextUID] {
					nextUID++
				}
				s.UID = nextUID
			}
			if s.UID < 1 || uids[s.UID] {
				return mp, fmt.Errorf("seat %d: uid %d is taken or not positive", s.Seat, s.UID)
			}
			uids[s.UID] = true
			if s.Name == "" {
				s.Name = "Player " + strconv.Itoa(s.Seat)
			}
			s.AI = ""
			s.token = randomHex(16)
		case "ai":
			if s.AI == "" {
				s.AI = "adaptive"
			}
			ok := false
			for _, k := range aiKeys {
				ok = ok || k == s.AI
			}
			if !ok {
				return mp, fmt.Errorf("seat %d: no AI %q", s.Seat, s.AI)
			}
			if s.Name == "" {
				s.Name = "AI: " + s.AI
			}
			s.UID = 0
		default:
			return mp, fmt.Errorf(`seat %d: kind is "human" or "ai"`, s.Seat)
		}
	}
	if humans == 0 {
		return mp, errors.New("a lobby needs a human seat (an all-AI game has nobody to host or watch it)")
	}
	return mp, nil
}

// matchFile is the server's --match file for the lobby.
func matchFile(l *Lobby, scenario string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "-- Written by server-host for lobby %s (%s).\n", l.ID, l.Name)
	fmt.Fprintf(&b, "MatchSeed = %d\n", 1+randomInt(1<<30))
	fmt.Fprintf(&b, "MatchLobbyControl = %s\n", luaString(l.Control))
	b.WriteString("MatchTokens = {")
	for _, s := range l.Seats {
		if s.Kind == "human" {
			fmt.Fprintf(&b, " ['%d'] = %s,", s.UID, luaString(s.token))
		}
	}
	b.WriteString(" }\nMatchConfig = {\n  GameMods = {},\n  Observers = {},\n  GameOptions = {\n")
	fmt.Fprintf(&b, "    ScenarioFile = %s,\n    TeamLock = 'locked',\n    AllowObservers = true,\n", luaString(scenario))
	keys := make([]string, 0, len(l.Options))
	for k := range l.Options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "    %s = %s,\n", k, luaString(l.Options[k]))
	}
	b.WriteString("  },\n  PlayerOptions = {\n")
	for _, s := range l.Seats {
		fmt.Fprintf(&b, "    [%d] = {\n      PlayerName = %s, ", s.Seat, luaString(s.Name))
		if s.Kind == "human" {
			fmt.Fprintf(&b, "Human = true, OwnerID = '%d', Ready = false,", s.UID)
		} else {
			fmt.Fprintf(&b, "Human = false, AIPersonality = %s, Ready = true,", luaString(s.AI))
		}
		fmt.Fprintf(&b, " Civilian = false,\n      Faction = %d, Team = %d, StartSpot = %d, MEAN = 1500, DEV = 500, PL = 1000,\n", s.Faction, s.Team, s.Seat)
		fmt.Fprintf(&b, "      NG = 0, DIV = '', Country = '', Clan = '', BadMap = false, PlayerColor = %d, ArmyColor = %d,\n    },\n", s.Seat, s.Seat)
	}
	b.WriteString("  },\n}\n")
	return b.String()
}

// pickCPUs chooses n CPUs for a lobby: those no running lobby holds first, then the least loaded.
func pickCPUs(cpus []CPU, n int) []int {
	c := append([]CPU(nil), cpus...)
	sort.SliceStable(c, func(i, j int) bool {
		if len(c[i].Lobbies) != len(c[j].Lobbies) {
			return len(c[i].Lobbies) < len(c[j].Lobbies)
		}
		if c[i].Load10 != c[j].Load10 {
			return c[i].Load10 < c[j].Load10
		}
		return c[i].ID < c[j].ID
	})
	if n > len(c) {
		n = len(c)
	}
	out := make([]int, 0, n)
	for _, x := range c[:n] {
		out = append(out, x.ID)
	}
	sort.Ints(out)
	return out
}

// cpusWithLobbies is the sampler's CPUs with each running lobby marked on its CPUs.
func (m *manager) cpusWithLobbies() []CPU {
	cpus := m.cpus()
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := map[int]int{}
	for i, c := range cpus {
		idx[c.ID] = i
	}
	ids := make([]string, 0, len(m.lobbies))
	for id := range m.lobbies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		l := m.lobbies[id]
		if !running(l.State) {
			continue
		}
		for _, c := range l.CPUs {
			if i, ok := idx[c]; ok {
				cpus[i].Lobbies = append(cpus[i].Lobbies, id)
			}
		}
	}
	return cpus
}

func cpuArg(cpus []int) string {
	parts := make([]string, len(cpus))
	for i, c := range cpus {
		parts[i] = strconv.Itoa(c)
	}
	return strings.Join(parts, ",")
}

func running(state string) bool { return state == "starting" || state == "lobby" || state == "game" }

func portFree(ip string, port int) bool {
	u, err := net.ListenPacket("udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	u.Close()
	t, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	t.Close()
	return true
}

func freeLocalTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// create starts a lobby: its folder, match file, token, and the server pinned to its CPUs.
func (m *manager) create(req CreateRequest) (*Lobby, int, error) {
	mp, err := m.validate(&req)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	hint := hintFor(len(req.Seats), mp.KM)
	cpuList := []int{}
	raw := strings.TrimSpace(string(req.CPUs))
	allCPUs := m.cpusWithLobbies()
	if raw == "" || raw == `"auto"` || raw == "null" {
		n := req.Cores
		if n <= 0 {
			n = hint.SuggestedCores
		}
		cpuList = pickCPUs(allCPUs, n)
	} else if err := json.Unmarshal(req.CPUs, &cpuList); err != nil {
		return nil, http.StatusBadRequest, errors.New(`cpus is a list of CPU ids or "auto"`)
	} else {
		known := map[int]bool{}
		for _, c := range allCPUs {
			known[c.ID] = true
		}
		seen := map[int]bool{}
		for _, c := range cpuList {
			if !known[c] || seen[c] {
				return nil, http.StatusBadRequest, fmt.Errorf("CPU %d isn't one of this machine's, or is listed twice", c)
			}
			seen[c] = true
		}
		sort.Ints(cpuList)
	}
	if len(cpuList) == 0 {
		return nil, http.StatusBadRequest, errors.New("no CPUs to run the lobby on")
	}

	m.mu.Lock()
	live := 0
	used := map[int]bool{}
	for _, l := range m.lobbies {
		if running(l.State) {
			live++
			used[l.Port] = true
		}
	}
	if live >= m.cfg.maxLobbies {
		m.mu.Unlock()
		return nil, http.StatusConflict, fmt.Errorf("this host runs at most %d lobbies", m.cfg.maxLobbies)
	}
	port := 0
	for p := m.cfg.portFirst; p <= m.cfg.portLast; p++ {
		if !used[p] && portFree(m.cfg.listenIP, p) {
			port = p
			break
		}
	}
	id := "l" + strconv.Itoa(m.next)
	m.next++
	m.mu.Unlock()
	if port == 0 {
		return nil, http.StatusConflict, fmt.Errorf("no free game port in %d-%d", m.cfg.portFirst, m.cfg.portLast)
	}
	restPort, err := freeLocalTCPPort()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if req.Name == "" {
		req.Name = mp.Name
	}
	opts := defaultOptions()
	for k, v := range req.Options {
		opts[k] = v
	}
	now := time.Now().UTC()
	l := &Lobby{ID: id, Name: req.Name, State: "starting", Map: LobbyMap{mp.ID, mp.Name, mp.KM, mp.Players}, Options: opts,
		CPUs: cpuList, Port: port, Created: now.Format(time.RFC3339), Control: req.Control, StartWhenReady: req.StartWhenReady,
		Seats: req.Seats, Hint: hint, restPort: restPort, restToken: randomHex(24), done: make(chan struct{})}
	l.Dir = filepath.Join(m.cfg.runsDir, id+"-"+now.Format("20060102-150405"))
	for i := range l.Seats {
		if s := &l.Seats[i]; s.Kind == "human" {
			s.Join = fmt.Sprintf("/connectserver %s:%d /servertoken %s /serveruid %d", m.cfg.publicHost, port, s.token, s.UID)
		}
	}
	if err := os.MkdirAll(filepath.Join(l.Dir, "out"), 0o755); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	matchPath := filepath.Join(l.Dir, "match.lua")
	tokenPath := filepath.Join(l.Dir, "rest.token")
	if err := os.WriteFile(matchPath, []byte(matchFile(l, mp.File)), 0o600); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if err := os.WriteFile(tokenPath, []byte(l.restToken+"\n"), 0o600); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	args := []string{"--match", matchPath, "--out", filepath.Join(l.Dir, "out"),
		"--listen", net.JoinHostPort(m.cfg.listenIP, strconv.Itoa(port)),
		"--lobby-seconds", strconv.Itoa(int(req.LobbyMinutes * 60)),
		"--rest", "127.0.0.1:" + strconv.Itoa(restPort), "--rest-token-file", tokenPath, "--cpus", cpuArg(cpuList)}
	if req.StartWhenReady > 0 {
		args = append(args, "--start-when-ready", strconv.FormatFloat(req.StartWhenReady, 'f', -1, 64))
	}
	args = append(args, m.cfg.engineArgs...)
	if len(cpuList) >= 2 {
		args = append(args, "/simworkers", strconv.Itoa(len(cpuList)-1))
	}
	logf, err := os.Create(filepath.Join(l.Dir, "server.log"))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	cmd := exec.Command(m.cfg.serverBin, args...)
	cmd.Dir = l.Dir
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := startPinned(cmd, cpuList); err != nil {
		logf.Close()
		return nil, http.StatusInternalServerError, fmt.Errorf("starting the server: %w", err)
	}
	l.proc = cmd.Process
	l.PID = cmd.Process.Pid
	l.CPUsAllowed = allowedCPUs(l.PID)
	m.mu.Lock()
	m.lobbies[id] = l
	m.mu.Unlock()
	go func() {
		err := cmd.Wait()
		logf.Close()
		m.mu.Lock()
		defer m.mu.Unlock()
		switch {
		case l.stopAsked:
			l.State = "stopped"
		case err == nil:
			l.State = "ended"
		default:
			l.State = "failed"
		}
		if err != nil {
			l.Exit = err.Error()
		} else {
			l.Exit = "exit 0"
		}
		close(l.done)
	}()
	go m.watch(l)
	return m.locked(l), http.StatusOK, nil
}

// watch reads the lobby's status from its own REST API until the process ends: every 0.5 s while it is
// starting, so the list shows "lobby" as soon as it answers, then every 2 s.
func (m *manager) watch(l *Lobby) {
	wait := 500 * time.Millisecond
	for {
		select {
		case <-l.done:
			return
		case <-time.After(wait):
		}
		phase, beat, ok := m.childStatus(l)
		m.mu.Lock()
		if ok && running(l.State) {
			l.Phase, l.Beat = phase, beat
			if phase == "lobby" || phase == "game" {
				l.State = phase
				wait = 2 * time.Second
			}
		}
		m.mu.Unlock()
	}
}

func (m *manager) childStatus(l *Lobby) (string, int, bool) {
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/v1/status", l.restPort), nil)
	req.Header.Set("Authorization", "Bearer "+l.restToken)
	resp, err := m.client.Do(req)
	if err != nil {
		return "", 0, false
	}
	defer resp.Body.Close()
	var st struct {
		Phase string `json:"phase"`
		Beat  int    `json:"beat"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&st) != nil {
		return "", 0, false
	}
	return st.Phase, st.Beat, true
}

// stop ends a lobby's server: SIGTERM, then a kill after 10 s.
func (m *manager) stop(id string) (*Lobby, error) {
	m.mu.Lock()
	l, ok := m.lobbies[id]
	if !ok {
		m.mu.Unlock()
		return nil, errNoLobby
	}
	if !running(l.State) {
		s := m.snapshot(l)
		m.mu.Unlock()
		return s, nil
	}
	l.stopAsked = true
	p := l.proc
	m.mu.Unlock()
	stopProcess(p, false)
	select {
	case <-l.done:
	case <-time.After(10 * time.Second):
		stopProcess(p, true)
		<-l.done
	}
	return m.locked(l), nil
}

func (m *manager) locked(l *Lobby) *Lobby {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshot(l)
}

func (m *manager) forget(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.lobbies[id]
	if !ok {
		return errNoLobby
	}
	if running(l.State) {
		return errors.New("stop the lobby first")
	}
	delete(m.lobbies, id)
	return nil
}

var errNoLobby = errors.New("no such lobby")

func (m *manager) stopAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.lobbies))
	for id, l := range m.lobbies {
		if running(l.State) {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) { defer wg.Done(); _, _ = m.stop(id) }(id)
	}
	wg.Wait()
}

// snapshot copies a lobby for a reply; the caller holds mu.
func (m *manager) snapshot(l *Lobby) *Lobby {
	c := *l
	c.Seats = append([]Seat(nil), l.Seats...)
	c.CPUs = append([]int(nil), l.CPUs...)
	c.Options = map[string]string{}
	for k, v := range l.Options {
		c.Options[k] = v
	}
	return &c
}

func (m *manager) list() []*Lobby {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Lobby, 0, len(m.lobbies))
	for _, l := range m.lobbies {
		out = append(out, m.snapshot(l))
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.Atoi(out[i].ID[1:])
		b, _ := strconv.Atoi(out[j].ID[1:])
		return a < b
	})
	return out
}

func (m *manager) get(id string) (*Lobby, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.lobbies[id]
	if !ok {
		return nil, false
	}
	return m.snapshot(l), true
}

// childREST is where a lobby's own API listens and its token, for the proxy.
func (m *manager) childREST(id string) (int, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.lobbies[id]
	if !ok || !running(l.State) {
		return 0, "", false
	}
	return l.restPort, l.restToken, true
}
