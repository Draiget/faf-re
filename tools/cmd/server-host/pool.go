package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

// Player hosting: the operator gives players a pool, the CPUs (whole cores, by NUMA node) their games may use, how
// many at once, the largest game, cores per game, lobby minutes, default settings and access. Players ask for a game
// with a request (requests.go); a request that doesn't fit waits in the pool's queue (queue.go). The operator's own
// lobbies use the CPUs outside the pool: Auto picks there while player hosting runs, and a CPU picked by hand inside
// it is warned (pool_overlap).

// Pool is the player-hosting settings.
type Pool struct {
	Enabled      bool           `json:"enabled"`
	CPUs         []int          `json:"cpus"`
	Nodes        []int          `json:"nodes"` // the NUMA nodes its CPUs are on
	MaxGames     int            `json:"max_games"`
	MaxPlayers   int            `json:"max_players"`
	Cores        int            `json:"cores"` // per game; 0: from the map size and players
	LobbyMinutes float64        `json:"lobby_minutes"`
	Access       string         `json:"access"` // open, or code
	Code         string         `json:"code"`
	Options      map[string]any `json:"options"` // the default settings of a player's game
	MaxQueue     int            `json:"max_queue"`
}

// PoolUpdate is PUT /api/v1/pool's body: any of the pool's fields, and drop_queue.
type PoolUpdate struct {
	Enabled      *bool           `json:"enabled"`
	CPUs         *[]int          `json:"cpus"`
	Nodes        *[]int          `json:"nodes"` // without cpus: every CPU of these nodes
	MaxGames     *int            `json:"max_games"`
	MaxPlayers   *int            `json:"max_players"`
	Cores        *int            `json:"cores"`
	LobbyMinutes *float64        `json:"lobby_minutes"`
	Access       *string         `json:"access"`
	Code         *string         `json:"code"`
	Options      *map[string]any `json:"options"`
	MaxQueue     *int            `json:"max_queue"`
	DropQueue    bool            `json:"drop_queue"` // with enabled false: cancel the queued requests too
}

// PoolUsage is what the pool runs now.
type PoolUsage struct {
	Games     int   `json:"games"`
	Queued    int   `json:"queued"`
	FreeCores int   `json:"free_cores"` // physical cores of the pool no lobby runs on
	CPUsBusy  []int `json:"cpus_busy"`  // the pool's CPUs a lobby runs on
}

func defaultPool() Pool {
	return Pool{CPUs: []int{}, Nodes: []int{}, MaxGames: 4, MaxPlayers: 8, LobbyMinutes: 60, Access: "open", Options: map[string]any{}, MaxQueue: 10}
}

func (p Pool) clone() Pool {
	c := p
	c.CPUs = append([]int{}, p.CPUs...)
	c.Nodes = append([]int{}, p.Nodes...)
	c.Options = map[string]any{}
	for k, v := range p.Options {
		c.Options[k] = v
	}
	return c
}

// validateOptions checks game options as a request gives them.
func validateOptions(options map[string]any) error {
	for k, v := range options {
		if !reOptionKey.MatchString(k) || fixedOptions[k] {
			return fmt.Errorf("game option %q can't be set", k)
		}
		switch value := v.(type) {
		case string:
			if len(value) > 64 || strings.ContainsAny(value, "\n\r") {
				return fmt.Errorf("game option %s: value too long or not one line", k)
			}
		case float64, bool:
		default:
			return fmt.Errorf("game option %s: a string, number or true/false", k)
		}
	}
	return nil
}

// parseCPUs reads a request's "cpus": a list of ids, or "auto" / nothing.
func parseCPUs(raw json.RawMessage) ([]int, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == `"auto"` || text == "null" {
		return nil, nil
	}
	var ids []int
	if err := json.Unmarshal(raw, &ids); err != nil || len(ids) == 0 {
		return nil, errors.New(`cpus is a list of CPU ids or "auto"`)
	}
	return ids, nil
}

// poolActive is whether the pool's CPUs are kept for player games: hosting on, or requests still queued (they drain
// after it is turned off). The caller holds mu.
func (m *manager) poolActive() bool {
	if m.pool.Enabled {
		return true
	}
	for _, q := range m.queue {
		if q.Side == "pool" {
			return true
		}
	}
	return false
}

// machineFor is the machine as one side places on it: a player game on the pool's CPUs; an operator's lobby off them
// while player hosting runs (by hand anywhere, with a warning on the pool's).
func (m *manager) machineFor(side string) *machine {
	mc := m.machine()
	m.mu.Lock()
	inPool := map[int]bool{}
	for _, c := range m.pool.CPUs {
		inPool[c] = true
	}
	active := m.poolActive()
	m.mu.Unlock()
	switch {
	case side == "pool":
		mc.allowed, mc.outsideCode = inPool, "outside_pool"
	case active && len(inPool) > 0:
		mc.allowed, mc.outsideCode = map[int]bool{}, "pool_overlap"
		for _, c := range mc.cpus {
			if !inPool[c.ID] {
				mc.allowed[c.ID] = true
			}
		}
	}
	return mc
}

// planOn is the planner's answer for a game on one side; on the pool, without cores or CPUs, the pool's cores per game.
func (m *manager) planOn(side string, req PlanRequest) Plan {
	mc := m.machineFor(side)
	if side == "pool" && req.Cores == 0 && len(req.CPUs) == 0 {
		m.mu.Lock()
		req.Cores = m.pool.Cores
		m.mu.Unlock()
	}
	return place(mc, req)
}

// poolView answers GET /api/v1/pool: the settings and what the pool runs now.
func (m *manager) poolView() (Pool, PoolUsage) {
	cpus := m.cpusWithLobbies()
	mc := &machine{cpus: cpus, nodes: m.nodes()}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.pool.clone()
	u := PoolUsage{CPUsBusy: []int{}}
	for _, l := range m.lobbies {
		if running(l.State) && l.Side == "pool" {
			u.Games++
		}
	}
	for _, q := range m.queue {
		if q.Side == "pool" {
			u.Queued++
		}
	}
	inPool := map[int]bool{}
	for _, c := range p.CPUs {
		inPool[c] = true
	}
	busy := map[int]bool{}
	for _, c := range cpus {
		if inPool[c.ID] && len(c.Lobbies) > 0 {
			busy[c.ID] = true
			u.CPUsBusy = append(u.CPUsBusy, c.ID)
		}
	}
	for _, pc := range mc.cores() {
		has, taken := false, false
		for _, id := range pc.cpus {
			has = has || inPool[id]
			taken = taken || busy[id]
		}
		if has && !taken {
			u.FreeCores++
		}
	}
	return p, u
}

// updatePool applies a PUT: checks every field, then sets them together. It answers the warnings of the new pool
// (an operator's lobby running on its CPUs keeps them until it ends: pool_overlap) and the requests the change
// cancelled.
func (m *manager) updatePool(u PoolUpdate) ([]Warning, error) {
	m.pumpMu.Lock()
	defer m.pumpMu.Unlock()
	cpus := m.cpusWithLobbies()
	nodes := m.nodes()
	known := map[int]bool{}
	for _, c := range cpus {
		known[c.ID] = true
	}
	m.mu.Lock()
	p := m.pool.clone()
	m.mu.Unlock()

	if u.Enabled != nil {
		p.Enabled = *u.Enabled
	}
	switch {
	case u.CPUs != nil:
		p.CPUs = append([]int{}, (*u.CPUs)...)
	case u.Nodes != nil:
		p.CPUs = []int{}
		for _, want := range *u.Nodes {
			found := false
			for _, n := range nodes {
				if n.ID == want {
					found = true
					p.CPUs = append(p.CPUs, n.CPUs...)
				}
			}
			if !found {
				return nil, fmt.Errorf("no NUMA node %d", want)
			}
		}
	}
	seen := map[int]bool{}
	for _, c := range p.CPUs {
		if !known[c] || seen[c] {
			return nil, fmt.Errorf("CPU %d isn't one of this machine's, or is listed twice", c)
		}
		seen[c] = true
	}
	sort.Ints(p.CPUs)
	if u.MaxGames != nil {
		p.MaxGames = *u.MaxGames
	}
	if u.MaxPlayers != nil {
		p.MaxPlayers = *u.MaxPlayers
	}
	if u.Cores != nil {
		p.Cores = *u.Cores
	}
	if u.LobbyMinutes != nil {
		p.LobbyMinutes = *u.LobbyMinutes
	}
	if u.Access != nil {
		p.Access = *u.Access
	}
	if u.Code != nil {
		p.Code = strings.TrimSpace(*u.Code)
	}
	if u.Options != nil {
		p.Options = map[string]any{}
		for k, v := range *u.Options {
			p.Options[k] = v
		}
	}
	if u.MaxQueue != nil {
		p.MaxQueue = *u.MaxQueue
	}
	switch {
	case p.MaxGames < 1 || p.MaxGames > 256:
		return nil, errors.New("max_games is 1..256")
	case p.MaxPlayers < 1 || p.MaxPlayers > kMaxPlayers:
		return nil, fmt.Errorf("max_players is 1..%d", kMaxPlayers)
	case p.Cores < 0 || p.Cores > 64:
		return nil, errors.New("cores is 0 (from the map size and players) to 64")
	case p.LobbyMinutes < 1 || p.LobbyMinutes > 24*60:
		return nil, errors.New("lobby_minutes is 1..1440")
	case p.Access != "open" && p.Access != "code":
		return nil, errors.New(`access is "open" or "code"`)
	case p.MaxQueue < 0 || p.MaxQueue > 1000:
		return nil, errors.New("max_queue is 0..1000")
	case len(p.Code) > 64 || strings.ContainsAny(p.Code, " \t\r\n"):
		return nil, errors.New("code is up to 64 characters without spaces")
	}
	if err := validateOptions(p.Options); err != nil {
		return nil, err
	}
	if p.Access == "code" && p.Code == "" {
		p.Code = randomHex(4)
	}
	if p.Enabled && len(p.CPUs) == 0 {
		return nil, errors.New("player hosting needs CPUs: cpus or nodes")
	}
	nodeOf := (&machine{nodes: nodes}).nodeOf()
	nodeSet := map[int]bool{}
	for _, c := range p.CPUs {
		nodeSet[nodeOf[c]] = true
	}
	p.Nodes = []int{}
	for n := range nodeSet {
		p.Nodes = append(p.Nodes, n)
	}
	sort.Ints(p.Nodes)

	var warnings []Warning
	inPool := map[int]bool{}
	for _, c := range p.CPUs {
		inPool[c] = true
	}
	m.mu.Lock()
	m.pool = p
	ids := make([]string, 0, len(m.lobbies))
	for id := range m.lobbies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		l := m.lobbies[id]
		if !running(l.State) || l.Side == "pool" {
			continue
		}
		for _, c := range l.CPUs {
			if inPool[c] {
				add(&warnings, "pool_overlap", "warn", "lobby %s runs on CPU %d of the pool and keeps it until it ends", l.ID, c)
			}
		}
	}
	if !p.Enabled && u.DropQueue {
		kept := m.queue[:0]
		for _, q := range m.queue {
			if q.Side != "pool" {
				kept = append(kept, q)
				continue
			}
			if r := m.requests[q.requestID]; r != nil {
				r.setEnded("cancelled", "player hosting was turned off")
			}
		}
		m.queue = kept
	}
	m.mu.Unlock()
	if warnings == nil {
		warnings = []Warning{}
	}
	m.savePool()
	m.kick()
	return warnings, nil
}

// savePool keeps the pool's settings in poolFile, so the host starts with them again.
func (m *manager) savePool() {
	if m.poolFile == "" {
		return
	}
	m.mu.Lock()
	data, err := json.MarshalIndent(m.pool, "", "  ")
	m.mu.Unlock()
	if err != nil {
		return
	}
	tmp := m.poolFile + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("pool settings not saved: %v", err)
		return
	}
	if err := os.Rename(tmp, m.poolFile); err != nil {
		log.Printf("pool settings not saved: %v", err)
	}
}

// loadPool reads the pool's settings kept by an earlier run; CPUs this machine doesn't have are dropped.
func (m *manager) loadPool() {
	if m.poolFile == "" {
		return
	}
	data, err := os.ReadFile(m.poolFile)
	if err != nil {
		return
	}
	p := defaultPool()
	if err := json.Unmarshal(data, &p); err != nil {
		log.Printf("pool settings in %s not read: %v", m.poolFile, err)
		return
	}
	if p.Options == nil {
		p.Options = map[string]any{}
	}
	known := map[int]bool{}
	for _, c := range m.cpus() {
		known[c.ID] = true
	}
	kept := []int{}
	for _, c := range p.CPUs {
		if known[c] {
			kept = append(kept, c)
		}
	}
	p.CPUs = kept
	if p.Enabled && len(p.CPUs) == 0 {
		p.Enabled = false
	}
	m.mu.Lock()
	m.pool = p
	m.mu.Unlock()
	log.Printf("player hosting: %v, pool CPUs %v (kept from the last run)", p.Enabled, p.CPUs)
}
