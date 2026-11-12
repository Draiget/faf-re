package main

import (
	"fmt"
	"sort"
)

// Plan WP17.17: what a game needs (cores, memory, upload) and where it goes, with the reasons it may not fit.

// Estimate is a game's measured cost for its size.
type Estimate struct {
	Players        int     `json:"players"`
	KM             int     `json:"km"`
	MeanCores      float64 `json:"mean_cores"`
	WorstCores     float64 `json:"worst_cores"`
	SuggestedCores int     `json:"suggested_cores"`
	MemoryMB       int     `json:"memory_mb"`
	UploadKBps     int     `json:"upload_kbps"`
	MinConnection  int     `json:"min_connection_kbps"`
	Basis          string  `json:"basis"`
}

// memoryFor is the server's peak memory for a game this size: measured peaks of recorded games played through the
// server on fw0 (tmp/claude/packing/sizes_summary.txt: 4 players 190 MB, 6 211, 8 297-337, 10 246, 12 390-406), with
// a quarter on top; 16 players is not measured (an estimate from the 12-player peak).
func memoryFor(players int) (mb int, basis string) {
	switch {
	case players <= 4:
		return 250, "measured peak 190 MB (4 players)"
	case players <= 6:
		return 270, "measured peak 211 MB (6 players)"
	case players <= 8:
		return 420, "measured peaks 297-337 MB (8 players)"
	case players <= 12:
		return 510, "measured peaks 390-406 MB (12 players)"
	default:
		return 640, "not measured: 16 players estimated from the 12-player peak"
	}
}

func estimateFor(players, km int) Estimate {
	h := hintFor(players, km)
	mem, memBasis := memoryFor(players)
	return Estimate{Players: h.Players, KM: h.KM, MeanCores: h.MeanCores, WorstCores: h.WorstCores, SuggestedCores: h.SuggestedCores,
		MemoryMB: mem, UploadKBps: h.ServerUploadKBps, MinConnection: h.MinConnectionKBps,
		Basis: h.Basis + "; memory: " + memBasis + ", plus a quarter; upload: " + h.ConnectionBasis}
}

// Warning is one reason a placement is worse than it could be, or doesn't fit.
type Warning struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // info, warn, error
	Text     string `json:"text"`
}

// Plan is a game's estimate and its CPUs.
type Plan struct {
	Estimate Estimate  `json:"estimate"`
	Cores    int       `json:"cores"`
	CPUs     []int     `json:"cpus"`
	Nodes    []int     `json:"nodes"` // the NUMA nodes its CPUs are on; one when it fits a node
	Fits     bool      `json:"fits"`  // no error
	Warnings []Warning `json:"warnings"`
}

// PlanRequest asks where a game goes: its size, and either a core count (0: the suggestion) or CPUs by hand.
type PlanRequest struct {
	Players int   `json:"players"`
	KM      int   `json:"km"`
	Cores   int   `json:"cores"`
	CPUs    []int `json:"cpus"`
}

// machine is what placement reads: CPUs (with the lobbies on each), nodes, links, and the running lobbies' upload.
type machine struct {
	cpus          []CPU
	nodes         []Node
	links         []Link
	lobbiesUpload int // KB/s, the running lobbies' estimates
	memAvailMB    int
}

type physCore struct {
	node, socket, core int
	cpus               []int // hyperthread siblings, sorted
}

func (m *machine) nodeOf() map[int]int {
	out := map[int]int{}
	for _, n := range m.nodes {
		for _, c := range n.CPUs {
			out[c] = n.ID
		}
	}
	return out
}

// cores groups logical CPUs into physical cores per node.
func (m *machine) cores() []physCore {
	nodeOf := m.nodeOf()
	byKey := map[[3]int]*physCore{}
	var keys [][3]int
	for _, c := range m.cpus {
		k := [3]int{nodeOf[c.ID], c.Socket, c.Core}
		pc, ok := byKey[k]
		if !ok {
			pc = &physCore{node: k[0], socket: k[1], core: k[2]}
			byKey[k] = pc
			keys = append(keys, k)
		}
		pc.cpus = append(pc.cpus, c.ID)
	}
	out := make([]physCore, 0, len(keys))
	for _, k := range keys {
		pc := byKey[k]
		sort.Ints(pc.cpus)
		out = append(out, *pc)
	}
	return out
}

func (m *machine) cpu(id int) (CPU, bool) {
	for _, c := range m.cpus {
		if c.ID == id {
			return c, true
		}
	}
	return CPU{}, false
}

func add(w *[]Warning, code, severity, format string, args ...any) {
	*w = append(*w, Warning{Code: code, Severity: severity, Text: fmt.Sprintf(format, args...)})
}

// place plans a game on the machine: the request's CPUs if given (checked), else `cores` (or the suggestion) picked
// inside one NUMA node on whole physical cores no running lobby uses, least loaded first.
func place(m *machine, req PlanRequest) Plan {
	est := estimateFor(req.Players, req.KM)
	p := Plan{Estimate: est, Warnings: []Warning{}}
	nodeOf := m.nodeOf()
	busy := func(c CPU) bool { return len(c.Lobbies) > 0 }

	if len(req.CPUs) > 0 {
		seen := map[int]bool{}
		for _, id := range req.CPUs {
			if _, ok := m.cpu(id); !ok || seen[id] {
				add(&p.Warnings, "unknown_cpu", "error", "CPU %d isn't one of this machine's, or is listed twice", id)
				continue
			}
			seen[id] = true
			p.CPUs = append(p.CPUs, id)
		}
		sort.Ints(p.CPUs)
	} else {
		want := req.Cores
		if want <= 0 {
			want = est.SuggestedCores
		}
		p.CPUs = autoPick(m, want, est.MemoryMB, &p.Warnings)
	}
	p.Cores = len(p.CPUs)

	// Where it landed.
	nodes := map[int]bool{}
	for _, id := range p.CPUs {
		nodes[nodeOf[id]] = true
	}
	for n := range nodes {
		p.Nodes = append(p.Nodes, n)
	}
	sort.Ints(p.Nodes)
	if len(p.Nodes) > 1 {
		add(&p.Warnings, "spans_nodes", "warn", "its CPUs are on NUMA nodes %v: the sim's memory is on one of them, so the others reach it across the socket link (slower); keep a game on one node", p.Nodes)
	}

	// Cores against the measured need.
	if p.Cores > 0 && float64(p.Cores) < est.WorstCores {
		add(&p.Warnings, "too_few_cores", "warn", "%d core(s) for a game whose worst 30 s took %.2f cores: it may fall behind in big fights; %d suggested", p.Cores, est.WorstCores, est.SuggestedCores)
	}
	if p.Cores > 1 && p.Cores > 2*est.SuggestedCores {
		add(&p.Warnings, "too_many_cores", "info", "%d cores for a game that needs about %d: the sim runs one main thread, so the rest mostly idle; %d would leave room for other lobbies", p.Cores, est.SuggestedCores, est.SuggestedCores)
	}

	// Sharing and load.
	byCore := map[[3]int][]int{}
	for _, id := range p.CPUs {
		c, _ := m.cpu(id)
		byCore[[3]int{nodeOf[id], c.Socket, c.Core}] = append(byCore[[3]int{nodeOf[id], c.Socket, c.Core}], id)
		if busy(c) {
			add(&p.Warnings, "shared_cpu", "warn", "CPU %d already runs lobby %v: both games compete for it", id, c.Lobbies)
		} else if c.Load10 >= 50 {
			add(&p.Warnings, "busy_cpu", "warn", "CPU %d is %.0f%% busy over the last 10 s (outside the lobbies)", id, c.Load10)
		}
	}
	for _, pc := range m.cores() {
		mine := byCore[[3]int{pc.node, pc.socket, pc.core}]
		if len(mine) == 0 || len(pc.cpus) < 2 {
			continue
		}
		if len(mine) >= 2 {
			add(&p.Warnings, "both_siblings", "info", "CPUs %v are the two hyperthreads of one physical core: they share its execution units, so together they do less than two separate cores", mine)
			continue
		}
		for _, sib := range pc.cpus {
			if sib == mine[0] {
				continue
			}
			if c, ok := m.cpu(sib); ok && busy(c) {
				add(&p.Warnings, "sibling_busy", "warn", "CPU %d shares its physical core with CPU %d, which runs lobby %v", mine[0], sib, c.Lobbies)
			}
		}
	}

	// Memory.
	if len(p.Nodes) == 1 {
		for _, n := range m.nodes {
			if n.ID == p.Nodes[0] && n.MemoryMB.Total > 0 && n.MemoryMB.Free < est.MemoryMB {
				add(&p.Warnings, "node_memory", "warn", "node %d has about %d MB free and the game takes about %d MB: part of its memory lands on the other node", n.ID, n.MemoryMB.Free, est.MemoryMB)
			}
		}
	}
	if m.memAvailMB > 0 && m.memAvailMB < est.MemoryMB {
		add(&p.Warnings, "memory", "error", "the machine has %d MB available and the game takes about %d MB", m.memAvailMB, est.MemoryMB)
	}

	// Network: every running lobby's upload estimate and this one's against the links.
	capacity := 0
	for _, l := range m.links {
		capacity += l.SpeedMbps * 125 // KB/s
	}
	if capacity > 0 {
		total := m.lobbiesUpload + est.UploadKBps
		if float64(total) > 0.8*float64(capacity) {
			severity := "warn"
			if total > capacity {
				severity = "error"
			}
			add(&p.Warnings, "network", severity, "the lobbies would send up to %d KB/s (this one %d) over %d KB/s of links (%d%%)", total, est.UploadKBps, capacity, total*100/capacity)
		}
	}
	if len(p.CPUs) == 0 {
		add(&p.Warnings, "no_cpus", "error", "no CPUs to run it on")
	}
	p.Fits = true
	for _, w := range p.Warnings {
		if w.Severity == "error" {
			p.Fits = false
		}
	}
	return p
}

// autoPick takes `want` CPUs, one per free physical core, inside the NUMA node that has the most free physical cores
// (enough of them first, then the most free memory, then the least load); short of free cores it uses the node's free
// hyperthread siblings, then the other nodes, saying so.
func autoPick(m *machine, want, memMB int, w *[]Warning) []int {
	type nodeInfo struct {
		id        int
		free      []physCore // no CPU of the core runs a lobby
		freeMemMB int
		load      float64
	}
	byNode := map[int]*nodeInfo{}
	for _, n := range m.nodes {
		byNode[n.ID] = &nodeInfo{id: n.ID, freeMemMB: n.MemoryMB.Free}
	}
	loadOf := map[int]float64{}
	lobbyOn := map[int]bool{}
	for _, c := range m.cpus {
		loadOf[c.ID] = c.Load10
		lobbyOn[c.ID] = len(c.Lobbies) > 0
	}
	for _, pc := range m.cores() {
		ni := byNode[pc.node]
		if ni == nil {
			continue
		}
		taken := false
		for _, id := range pc.cpus {
			taken = taken || lobbyOn[id]
			ni.load += loadOf[id]
		}
		if !taken {
			ni.free = append(ni.free, pc)
		}
	}
	nodes := make([]*nodeInfo, 0, len(byNode))
	for _, ni := range byNode {
		nodes = append(nodes, ni)
	}
	sort.Slice(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		if (len(a.free) >= want) != (len(b.free) >= want) {
			return len(a.free) >= want
		}
		if (a.freeMemMB >= memMB) != (b.freeMemMB >= memMB) {
			return a.freeMemMB >= memMB
		}
		if len(a.free) != len(b.free) {
			return len(a.free) > len(b.free)
		}
		return a.load < b.load
	})
	var out []int
	pickFrom := func(ni *nodeInfo) {
		cores := append([]physCore(nil), ni.free...)
		sort.Slice(cores, func(i, j int) bool { return loadOf[cores[i].cpus[0]] < loadOf[cores[j].cpus[0]] })
		for _, pc := range cores {
			if len(out) == want {
				return
			}
			out = append(out, pc.cpus[0])
		}
		// Short of whole cores: the free siblings of the cores just taken.
		for _, pc := range cores {
			for _, id := range pc.cpus[1:] {
				if len(out) == want {
					return
				}
				if !contains(out, id) {
					out = append(out, id)
				}
			}
		}
	}
	if len(nodes) > 0 {
		pickFrom(nodes[0])
		if free := len(nodes[0].free); free < want {
			if len(out) == want {
				add(w, "node_short", "warn", "NUMA node %d has %d free physical core(s) for %d wanted: the rest are hyperthread siblings of those", nodes[0].id, free, want)
			} else {
				add(w, "node_short", "warn", "NUMA node %d has %d free physical core(s) for %d wanted: the rest come from another node", nodes[0].id, free, want)
			}
		}
		for _, ni := range nodes[1:] {
			if len(out) == want {
				break
			}
			pickFrom(ni)
		}
	}
	if len(out) < want {
		add(w, "machine_short", "error", "only %d free CPU(s) (no lobby on them) for %d wanted: stop a lobby or choose CPUs by hand (shared)", len(out), want)
	}
	sort.Ints(out)
	return out
}

func contains(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
