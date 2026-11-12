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

// Observer is one person allowed to watch a lobby's game (plan WP13.1/WP17.5): its own token, the
// game's replay from the lobby's observe port, ObserverDelaySeconds late unless a referee.
type Observer struct {
	Name    string `json:"name"`
	Referee bool   `json:"referee"`
	Watch   string `json:"watch,omitempty"`
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
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	State          string         `json:"state"` // starting, lobby, game, ended, failed, stopped
	Map            LobbyMap       `json:"map"`
	Options        map[string]any `json:"options"`
	CPUs           []int          `json:"cpus"`
	CPUsAllowed    string         `json:"cpus_allowed,omitempty"`
	Port           int            `json:"port"`
	PID            int            `json:"pid"`
	Created        string         `json:"created"`
	Control        string         `json:"control"`
	StartWhenReady float64        `json:"start_when_ready"`
	Seats          []Seat         `json:"seats"`
	Observers      []Observer     `json:"observers"`
	ObserverDelay  float64        `json:"observer_delay_seconds"`
	ObservePort    int            `json:"observe_port,omitempty"`
	Hint           Hint           `json:"hint"`
	Nodes          []int          `json:"nodes"`      // plan WP17.17: the NUMA nodes its CPUs are on
	Warnings       []Warning      `json:"warnings"`   // the placement's, when it was made
	Usage          procUsage      `json:"usage"`      // plan WP17.16: its server process, sampled every 2 s
	Kind           string         `json:"kind"`       // tournament (organiser's) or custom (a player hosts)
	Side           string         `json:"side"`       // operator, or pool (a player's request on the pool's CPUs)
	Request        *string        `json:"request"`    // the player request it came from
	QueuedAt       *string        `json:"queued_at"`  // when it was queued, if it waited
	StartedAt      string         `json:"started_at"` // when its server started
	Phase          string         `json:"phase"`
	Beat           int            `json:"beat"`
	Exit           string         `json:"exit"`
	Dir            string         `json:"dir"`

	restPort   int
	lastTicks  uint64
	lastSample time.Time
	restToken  string
	proc       *os.Process
	stopAsked  bool
	done       chan struct{}
}

// CreateRequest is POST /api/v1/lobbies's body.
type CreateRequest struct {
	Name           string          `json:"name"`
	Map            string          `json:"map"`
	Options        map[string]any  `json:"options"`
	Seats          []Seat          `json:"seats"`
	Observers      []Observer      `json:"observers"`
	ObserverDelay  float64         `json:"observer_delay_seconds"`
	Control        string          `json:"control"`
	StartWhenReady float64         `json:"start_when_ready"`
	LobbyMinutes   float64         `json:"lobby_minutes"`
	CPUs           json.RawMessage `json:"cpus"` // [ids] or "auto"
	Cores          int             `json:"cores"`
	Force          bool            `json:"force"` // start even when the placement says it doesn't fit
	Kind           string          `json:"kind"`  // tournament or custom; default from control
	Queue          bool            `json:"queue"` // wait in the operator queue when it doesn't fit now
}

// clone copies a request deeply enough that validating the copy leaves the original as it was.
func (r CreateRequest) clone() CreateRequest {
	c := r
	c.Seats = append([]Seat(nil), r.Seats...)
	c.Observers = append([]Observer(nil), r.Observers...)
	c.CPUs = append(json.RawMessage(nil), r.CPUs...)
	if r.Options != nil {
		c.Options = map[string]any{}
		for k, v := range r.Options {
			c.Options[k] = v
		}
	}
	return c
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
	nodes   func() []Node
	links   func() []Link
	procDir string
	// Plan WP17.20: FAF's settings and defaults; nil without them (tests).
	settings *settingsSource

	// Player hosting: the pool's settings, the queue (both sides, in order), the players' requests.
	pool        Pool
	poolFile    string // where the pool's settings are kept between runs; "" for nowhere
	queue       []*QueueItem
	nextQueue   int
	requests    map[string]*PlayerRequest
	nextRequest int
	rate        map[string][]time.Time // public request attempts per address, the last minute
	// startMu makes placing and starting one lobby at a time, so two starts can't take the same CPUs; pumpMu makes
	// the queue's changes and starts one at a time (taken before startMu, never inside it).
	startMu  sync.Mutex
	pumpMu   sync.Mutex
	kickCh   chan struct{}
	stopping bool // the host is stopping: nothing new starts (the queue would refill what stopAll ends)
}

func newManager(cfg config, maps func() []Map, cpus func() []CPU) *manager {
	m := &manager{cfg: cfg, lobbies: map[string]*Lobby{}, next: 1, maps: maps, cpus: cpus, client: &http.Client{Timeout: 3 * time.Second},
		procDir: "/proc", links: func() []Link { return nil }, pool: defaultPool(), nextQueue: 1, requests: map[string]*PlayerRequest{},
		nextRequest: 1, rate: map[string][]time.Time{}, kickCh: make(chan struct{}, 1)}
	// Without NUMA information (tests, a machine without /sys): one node holding every CPU.
	m.nodes = func() []Node {
		ids := []int{}
		for _, c := range cpus() {
			ids = append(ids, c.ID)
		}
		return []Node{{ID: 0, CPUs: ids}}
	}
	return m
}

var (
	reOptionKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	aiKeys      = []string{"easy", "medium", "adaptive", "rush", "turtle", "tech", "random", "adaptivecheat", "rushcheat", "turtlecheat", "techcheat", "randomcheat"}
	// Options the host sets itself; a request can't change them.
	fixedOptions = map[string]bool{"ScenarioFile": true, "TeamLock": true}
)

// defaultOptions is what a lobby starts from when the settings catalog can't be read (WP17.20 gives FAF's own).
func defaultOptions() map[string]any {
	return map[string]any{
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

// luaValue writes an option's value for Lua: a string quoted, a number as it is, true/false.
func luaValue(v any) string {
	switch value := v.(type) {
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	case string:
		return luaString(value)
	default:
		return luaString(fmt.Sprint(value))
	}
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
		if req.Kind == "tournament" {
			req.Control = "organiser"
		}
	case "player", "organiser":
	default:
		return mp, errors.New(`control is "player" or "organiser"`)
	}
	switch req.Kind {
	case "":
		req.Kind = "custom"
		if req.Control == "organiser" {
			req.Kind = "tournament"
		}
	case "tournament", "custom":
	default:
		return mp, errors.New(`kind is "tournament" or "custom"`)
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
	if err := validateOptions(req.Options); err != nil {
		return mp, err
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
			for _, k := range m.aiKeys() {
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
	if len(req.Observers) > 32 {
		return mp, errors.New("at most 32 observers")
	}
	if req.ObserverDelay < 0 || req.ObserverDelay > 3600 {
		return mp, errors.New("observer_delay_seconds is 0..3600")
	}
	for i := range req.Observers {
		o := &req.Observers[i]
		if len(o.Name) > 40 {
			return mp, fmt.Errorf("observer %d: name too long", i+1)
		}
		if o.Name == "" {
			o.Name = "Observer " + strconv.Itoa(i+1)
		}
		o.token = randomHex(16)
		o.Watch = ""
	}
	return mp, nil
}

// aiKeys is the AIs a seat may be: the settings catalog's (FAF's aitypes.lua, as the server describes it) when the
// host has one, else the built-in list.
func (m *manager) aiKeys() []string {
	if m.settings != nil {
		if s, err := m.settings.get(nil); err == nil && len(s.AI) > 0 {
			keys := make([]string, len(s.AI))
			for i, a := range s.AI {
				keys[i] = a.Key
			}
			return keys
		}
	}
	return aiKeys
}

// matchFile is the server's --match file for the lobby.
func matchFile(l *Lobby, scenario string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "-- Written by server-host for lobby %s (%s).\n", l.ID, l.Name)
	fmt.Fprintf(&b, "MatchSeed = %d\n", 1+randomInt(1<<30))
	fmt.Fprintf(&b, "MatchLobbyControl = %s\n", luaString(l.Control))
	if len(l.Observers) > 0 {
		var watchers, referees []string
		for _, o := range l.Observers {
			if o.Referee {
				referees = append(referees, luaString(o.token))
			} else {
				watchers = append(watchers, luaString(o.token))
			}
		}
		fmt.Fprintf(&b, "MatchObservers = { %s }\nMatchReferees = { %s }\n", strings.Join(watchers, ", "), strings.Join(referees, ", "))
	}
	// Plan WPR.8: the published minimum each player needs down goes with the match; the server shows it.
	rules := []string{fmt.Sprintf("MinConnectionKBps = %d", l.Hint.MinConnectionKBps)}
	if len(l.Observers) > 0 {
		rules = append(rules, "ObserverDelaySeconds = "+strconv.FormatFloat(l.ObserverDelay, 'f', -1, 64))
	}
	fmt.Fprintf(&b, "MatchRules = { %s }\n", strings.Join(rules, ", "))
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
		fmt.Fprintf(&b, "    %s = %s,\n", k, luaValue(l.Options[k]))
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

// cpusWithLobbies is the sampler's CPUs with each running lobby marked on its CPUs.
func (m *manager) cpusWithLobbies() []CPU {
	cpus := m.cpus()
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := map[int]int{}
	for i, c := range cpus {
		idx[c.ID] = i
	}
	for _, n := range m.nodes() {
		for _, c := range n.CPUs {
			if i, ok := idx[c]; ok {
				cpus[i].Node = n.ID
			}
		}
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

// machine is the placement engine's view: CPUs with the lobbies on them, NUMA nodes, links, the running lobbies'
// upload estimates and the memory available.
func (m *manager) machine() *machine {
	mc := &machine{cpus: m.cpusWithLobbies(), nodes: m.nodes(), links: m.links()}
	m.mu.Lock()
	for _, l := range m.lobbies {
		if running(l.State) {
			mc.lobbiesUpload += l.Hint.ServerUploadKBps
		}
	}
	m.mu.Unlock()
	_, mc.memAvailMB = memoryMB(m.procDir)
	return mc
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

// need is what a lobby asks of the machine, for the check whether it can start now.
type need struct {
	side    string // operator or pool
	players int
	km      int
	cores   int
	cpus    []int
	force   bool
	ports   int // 1, or 2 with observers
}

func needOf(req *CreateRequest, mp LobbyMap, side string) (need, error) {
	n := need{side: side, players: len(req.Seats), km: mp.KM, cores: req.Cores, force: req.Force, ports: 1}
	if len(req.Observers) > 0 {
		n.ports = 2
	}
	var err error
	n.cpus, err = parseCPUs(req.CPUs)
	return n, err
}

// usedPorts is the game and observe ports of the running lobbies; the caller holds mu.
func (m *manager) usedPorts() map[int]bool {
	used := map[int]bool{}
	for _, l := range m.lobbies {
		if running(l.State) {
			used[l.Port] = true
			if l.ObservePort != 0 {
				used[l.ObservePort] = true
			}
		}
	}
	return used
}

// fit checks whether a lobby can start now on mc: the host's and the pool's game limits, the placement, the ports.
// When it can't for want of capacity, waiting names what it waits for (games, cores, memory, network, ports) and code
// is 409; a request that can never start this way is 400 with no waiting.
func (m *manager) fit(mc *machine, n need) (plan Plan, waiting string, code int, err error) {
	m.mu.Lock()
	live, poolGames := 0, 0
	for _, l := range m.lobbies {
		if running(l.State) {
			live++
			if l.Side == "pool" {
				poolGames++
			}
		}
	}
	freePorts := m.cfg.portLast - m.cfg.portFirst + 1
	for p := range m.usedPorts() {
		if p >= m.cfg.portFirst && p <= m.cfg.portLast {
			freePorts--
		}
	}
	pool := m.pool
	m.mu.Unlock()
	if live >= m.cfg.maxLobbies {
		return plan, "games", http.StatusConflict, fmt.Errorf("this host runs at most %d lobbies at once", m.cfg.maxLobbies)
	}
	if n.side == "pool" {
		if poolGames >= pool.MaxGames {
			return plan, "games", http.StatusConflict, fmt.Errorf("the player pool runs at most %d games at once", pool.MaxGames)
		}
		if n.cores == 0 {
			n.cores = pool.Cores
		}
	}
	// Plan WP17.17: the placement engine picks or checks the CPUs, inside one NUMA node where it can.
	plan = place(mc, PlanRequest{Players: n.players, KM: n.km, Cores: n.cores, CPUs: n.cpus})
	if !plan.Fits && !n.force {
		var why []string
		waiting = ""
		for _, w := range plan.Warnings {
			if w.Severity != "error" {
				continue
			}
			why = append(why, w.Text)
			switch w.Code {
			case "unknown_cpu":
				return plan, "", http.StatusBadRequest, errors.New(w.Text)
			case "machine_short", "no_cpus":
				if waiting == "" || waiting == "network" || waiting == "memory" {
					waiting = "cores"
				}
			case "memory":
				if waiting == "" || waiting == "network" {
					waiting = "memory"
				}
			case "network":
				if waiting == "" {
					waiting = "network"
				}
			}
		}
		if waiting == "" {
			waiting = "cores"
		}
		if n.side == "pool" {
			return plan, waiting, http.StatusConflict, fmt.Errorf("no room in the player pool now: %s", strings.Join(why, "; "))
		}
		return plan, waiting, http.StatusConflict, fmt.Errorf("doesn't fit (force to start anyway): %s", strings.Join(why, "; "))
	}
	if len(plan.CPUs) == 0 {
		return plan, "", http.StatusBadRequest, errors.New("no CPUs to run the lobby on")
	}
	if freePorts < n.ports {
		return plan, "ports", http.StatusConflict, fmt.Errorf("no %d free ports in %d-%d", n.ports, m.cfg.portFirst, m.cfg.portLast)
	}
	return plan, "", http.StatusOK, nil
}

// startOpts says where a lobby comes from: its side, the player request and when it was queued.
type startOpts struct {
	side     string
	request  string
	queuedAt time.Time
}

// create starts an operator's lobby now: its folder, match file, token, and the server pinned to its CPUs.
func (m *manager) create(req CreateRequest) (*Lobby, int, error) {
	l, code, _, err := m.start(req, startOpts{side: "operator"})
	return l, code, err
}

// start starts a lobby on its side, or says why not; waiting is set when it fails for want of capacity (it may wait in
// the queue). One start at a time, so the placement it checks is the one it gets.
func (m *manager) start(req CreateRequest, o startOpts) (*Lobby, int, string, error) {
	m.startMu.Lock()
	defer m.startMu.Unlock()
	m.mu.Lock()
	stopping := m.stopping
	m.mu.Unlock()
	if stopping {
		return nil, http.StatusServiceUnavailable, "", errors.New("the host is stopping")
	}
	mp, err := m.validate(&req)
	if err != nil {
		return nil, http.StatusBadRequest, "", err
	}
	hint := hintFor(len(req.Seats), mp.KM)
	n, err := needOf(&req, LobbyMap{mp.ID, mp.Name, mp.KM, mp.Players}, o.side)
	if err != nil {
		return nil, http.StatusBadRequest, "", err
	}
	plan, waiting, code, err := m.fit(m.machineFor(o.side), n)
	if err != nil {
		return nil, code, waiting, err
	}
	cpuList := plan.CPUs

	m.mu.Lock()
	used := m.usedPorts()
	// A game port, and with observers a second one they watch from.
	wanted := n.ports
	var ports []int
	for p := m.cfg.portFirst; p <= m.cfg.portLast && len(ports) < wanted; p++ {
		if !used[p] && portFree(m.cfg.listenIP, p) {
			ports = append(ports, p)
		}
	}
	id := "l" + strconv.Itoa(m.next)
	m.next++
	m.mu.Unlock()
	if len(ports) < wanted {
		return nil, http.StatusConflict, "ports", fmt.Errorf("no %d free ports in %d-%d", wanted, m.cfg.portFirst, m.cfg.portLast)
	}
	port := ports[0]
	observePort := 0
	if wanted == 2 {
		observePort = ports[1]
	}
	restPort, err := freeLocalTCPPort()
	if err != nil {
		return nil, http.StatusInternalServerError, "", err
	}
	if req.Name == "" {
		req.Name = mp.Name
	}
	// Plan WP17.20: every option at FAF's default (the game's and the map's own), then the request's.
	opts := defaultOptions()
	if m.settings != nil {
		if s, err := m.settings.get(&mp); err == nil {
			opts = map[string]any{}
			for _, o := range append(s.Options, s.MapOptions...) {
				opts[o.Key] = o.Default
			}
		}
	}
	for k, v := range req.Options {
		opts[k] = v
	}
	now := time.Now().UTC()
	l := &Lobby{ID: id, Name: req.Name, State: "starting", Map: LobbyMap{mp.ID, mp.Name, mp.KM, mp.Players}, Options: opts,
		CPUs: cpuList, Port: port, Created: now.Format(time.RFC3339), Control: req.Control, StartWhenReady: req.StartWhenReady,
		Seats: req.Seats, Observers: req.Observers, ObserverDelay: req.ObserverDelay, ObservePort: observePort,
		Hint: hint, Nodes: plan.Nodes, Warnings: plan.Warnings, Kind: req.Kind, Side: o.side, StartedAt: now.Format(time.RFC3339),
		restPort: restPort, restToken: randomHex(24), done: make(chan struct{})}
	if o.request != "" {
		r := o.request
		l.Request = &r
	}
	if !o.queuedAt.IsZero() {
		q := o.queuedAt.UTC().Format(time.RFC3339)
		l.QueuedAt = &q
	}
	if l.Observers == nil {
		l.Observers = []Observer{}
	}
	for i := range l.Observers {
		l.Observers[i].Watch = fmt.Sprintf("/replay gpgnet://%s:%d/%s", m.cfg.publicHost, observePort, l.Observers[i].token)
	}
	l.Dir = filepath.Join(m.cfg.runsDir, id+"-"+now.Format("20060102-150405"))
	for i := range l.Seats {
		if s := &l.Seats[i]; s.Kind == "human" {
			s.Join = fmt.Sprintf("/connectserver %s:%d /servertoken %s /serveruid %d", m.cfg.publicHost, port, s.token, s.UID)
		}
	}
	if err := os.MkdirAll(filepath.Join(l.Dir, "out"), 0o755); err != nil {
		return nil, http.StatusInternalServerError, "", err
	}
	matchPath := filepath.Join(l.Dir, "match.lua")
	tokenPath := filepath.Join(l.Dir, "rest.token")
	if err := os.WriteFile(matchPath, []byte(matchFile(l, mp.File)), 0o600); err != nil {
		return nil, http.StatusInternalServerError, "", err
	}
	if err := os.WriteFile(tokenPath, []byte(l.restToken+"\n"), 0o600); err != nil {
		return nil, http.StatusInternalServerError, "", err
	}
	args := []string{"--match", matchPath, "--out", filepath.Join(l.Dir, "out"),
		"--listen", net.JoinHostPort(m.cfg.listenIP, strconv.Itoa(port)),
		"--lobby-seconds", strconv.Itoa(int(req.LobbyMinutes * 60)),
		"--rest", "127.0.0.1:" + strconv.Itoa(restPort), "--rest-token-file", tokenPath, "--cpus", cpuArg(cpuList)}
	if observePort != 0 {
		args = append(args, "--observe", net.JoinHostPort(m.cfg.listenIP, strconv.Itoa(observePort)))
	}
	if req.StartWhenReady > 0 {
		args = append(args, "--start-when-ready", strconv.FormatFloat(req.StartWhenReady, 'f', -1, 64))
	}
	args = append(args, m.cfg.engineArgs...)
	if len(cpuList) >= 2 {
		args = append(args, "/simworkers", strconv.Itoa(len(cpuList)-1))
	}
	logf, err := os.Create(filepath.Join(l.Dir, "server.log"))
	if err != nil {
		return nil, http.StatusInternalServerError, "", err
	}
	cmd := exec.Command(m.cfg.serverBin, args...)
	cmd.Dir = l.Dir
	cmd.Stdout, cmd.Stderr = logf, logf
	memNote, err := startPinned(cmd, cpuList, l.Nodes)
	if memNote != "" {
		l.Warnings = append(l.Warnings, Warning{Code: "memory_policy", Severity: "warn", Text: memNote})
	}
	if err != nil {
		logf.Close()
		return nil, http.StatusInternalServerError, "", fmt.Errorf("starting the server: %w", err)
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
		m.lobbyEnded(l)
		close(l.done)
	}()
	go m.watch(l)
	return m.locked(l), http.StatusOK, "", nil
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
		ticks, rssKB, pok := procTicks(m.procDir, l.PID)
		now := time.Now()
		m.mu.Lock()
		if pok {
			if !l.lastSample.IsZero() && ticks >= l.lastTicks {
				// Clock ticks are 1/100 s on Linux (USER_HZ).
				l.Usage.CPUCores = round1(float64(ticks-l.lastTicks)/100/now.Sub(l.lastSample).Seconds()*10) / 10
			}
			l.Usage.RSSMB = rssKB / 1024
			l.lastTicks, l.lastSample = ticks, now
		}
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
	m.startMu.Lock() // a start under way finishes first, so its lobby is stopped too
	m.mu.Lock()
	m.stopping = true
	m.mu.Unlock()
	m.startMu.Unlock()
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
	c.Observers = append([]Observer{}, l.Observers...)
	c.CPUs = append([]int(nil), l.CPUs...)
	c.Options = map[string]any{}
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
