package main

import (
	"strings"
	"testing"
)

// The test server's shape, smaller: 2 NUMA nodes, CPUs interleaved (node 0 even, node 1 odd), 4 physical cores a node with 2
// hyperthreads each (siblings 0/8, 2/10, ... on node 0).
func twoNodeMachine() *machine {
	m := &machine{memAvailMB: 40000}
	for id := 0; id < 16; id++ {
		node := id % 2
		core := (id % 8) / 2 // siblings: id and id+8
		m.cpus = append(m.cpus, CPU{ID: id, Socket: node, Core: core, Lobbies: []string{}})
	}
	for n := 0; n < 2; n++ {
		node := Node{ID: n}
		for id := n; id < 16; id += 2 {
			node.CPUs = append(node.CPUs, id)
		}
		node.MemoryMB.Total, node.MemoryMB.Free = 24000, 20000
		m.nodes = append(m.nodes, node)
	}
	return m
}

func codes(p Plan) string {
	var c []string
	for _, w := range p.Warnings {
		c = append(c, w.Code)
	}
	return strings.Join(c, ",")
}

func TestPlaceKeepsOneNodeAndWholeCores(t *testing.T) {
	m := twoNodeMachine()
	p := place(m, PlanRequest{Players: 8, KM: 20, Cores: 3})
	if len(p.Nodes) != 1 || len(p.CPUs) != 3 || !p.Fits {
		t.Fatalf("plan %+v", p)
	}
	cores := map[[2]int]bool{}
	for _, id := range p.CPUs {
		c, _ := m.cpu(id)
		if id%2 != p.Nodes[0] {
			t.Fatalf("CPU %d not on node %d", id, p.Nodes[0])
		}
		cores[[2]int{c.Socket, c.Core}] = true
	}
	if len(cores) != 3 {
		t.Fatalf("CPUs %v share physical cores", p.CPUs)
	}
	if strings.Contains(codes(p), "spans_nodes") || strings.Contains(codes(p), "both_siblings") {
		t.Fatalf("warnings %s", codes(p))
	}
}

func TestPlaceAvoidsTakenNode(t *testing.T) {
	m := twoNodeMachine()
	for i := range m.cpus { // a lobby on every core of node 0
		if m.cpus[i].ID%2 == 0 {
			m.cpus[i].Lobbies = []string{"l1"}
		}
	}
	p := place(m, PlanRequest{Players: 2, KM: 10, Cores: 2})
	if len(p.Nodes) != 1 || p.Nodes[0] != 1 || codes(p) != "" {
		t.Fatalf("plan %+v warnings %s", p, codes(p))
	}
}

func TestPlaceShortOfCores(t *testing.T) {
	m := twoNodeMachine()
	p := place(m, PlanRequest{Players: 8, KM: 20, Cores: 6}) // 4 whole cores a node
	if !strings.Contains(codes(p), "node_short") || len(p.Nodes) != 1 || len(p.CPUs) != 6 || !strings.Contains(codes(p), "both_siblings") {
		t.Fatalf("plan %+v warnings %s", p, codes(p))
	}
	for i := range m.cpus {
		m.cpus[i].Lobbies = []string{"lx"}
	}
	p = place(m, PlanRequest{Players: 2, KM: 10, Cores: 1})
	if p.Fits || !strings.Contains(codes(p), "machine_short") {
		t.Fatalf("a full machine fits: %+v %s", p, codes(p))
	}
}

func TestPlaceManualChecks(t *testing.T) {
	m := twoNodeMachine()
	m.cpus[4].Lobbies = []string{"l1"}
	p := place(m, PlanRequest{Players: 2, KM: 10, CPUs: []int{1, 4, 99}})
	c := codes(p)
	for _, want := range []string{"unknown_cpu", "spans_nodes", "shared_cpu"} {
		if !strings.Contains(c, want) {
			t.Errorf("manual pick lacks %s: %s", want, c)
		}
	}
	if p.Fits {
		t.Error("an unknown CPU fits")
	}
	if p = place(m, PlanRequest{Players: 2, KM: 10, CPUs: []int{1, 9}}); !strings.Contains(codes(p), "both_siblings") {
		t.Errorf("siblings 1 and 9: %s", codes(p))
	}
	m.cpus[3].Load10 = 80
	if p = place(m, PlanRequest{Players: 2, KM: 10, CPUs: []int{3}}); !strings.Contains(codes(p), "busy_cpu") {
		t.Errorf("busy CPU: %s", codes(p))
	}
}

func TestPlaceCoreCountAdvice(t *testing.T) {
	m := twoNodeMachine()
	if p := place(m, PlanRequest{Players: 2, KM: 10, Cores: 4}); !strings.Contains(codes(p), "too_many_cores") {
		t.Errorf("4 cores for a 1v1: %s", codes(p))
	}
	if p := place(m, PlanRequest{Players: 16, KM: 81, Cores: 1}); !strings.Contains(codes(p), "too_few_cores") {
		t.Errorf("1 core for 16 players on 81 km: %s (worst %.2f)", codes(p), p.Estimate.WorstCores)
	}
	if p := place(m, PlanRequest{Players: 2, KM: 10}); p.Cores != p.Estimate.SuggestedCores {
		t.Errorf("no core count: %d, suggested %d", p.Cores, p.Estimate.SuggestedCores)
	}
}

func TestPlaceMemoryAndNetwork(t *testing.T) {
	m := twoNodeMachine()
	m.memAvailMB = 100
	if p := place(m, PlanRequest{Players: 2, KM: 10, Cores: 1}); p.Fits || !strings.Contains(codes(p), "memory") {
		t.Errorf("100 MB available: %s", codes(p))
	}
	m = twoNodeMachine()
	m.nodes[0].MemoryMB.Free, m.nodes[1].MemoryMB.Free = 100, 100
	if p := place(m, PlanRequest{Players: 2, KM: 10, Cores: 1}); !strings.Contains(codes(p), "node_memory") {
		t.Errorf("100 MB free on each node: %s", codes(p))
	}
	m = twoNodeMachine()
	m.links = []Link{{Name: "eno1", SpeedMbps: 10}} // 1250 KB/s
	m.lobbiesUpload = 2300
	if p := place(m, PlanRequest{Players: 8, KM: 20, Cores: 1}); p.Fits || !strings.Contains(codes(p), "network") {
		t.Errorf("10 Mbit link: %s", codes(p))
	}
}

func TestParseCPUListAndNodeMeminfo(t *testing.T) {
	if got := parseCPUList("0,2,4-6,9\n"); len(got) != 6 || got[3] != 5 {
		t.Fatalf("got %v", got)
	}
	kb := nodeMeminfoKB("Node 1 MemTotal:       24766524 kB\nNode 1 MemFree:         3431032 kB\nNode 1 Inactive(file):  1000 kB\n")
	if kb["MemTotal"] != 24766524 || kb["Inactive(file)"] != 1000 {
		t.Fatalf("got %v", kb)
	}
}

func TestParseSettings(t *testing.T) {
	data := []byte(`{"lobby": {"globalOpts": [
	  {"key": "Victory", "label": "<LOC x>Victory Condition", "default": 1, "values": [{"key": "demoralization", "text": "<LOC y>Assassination"}, {"key": "sandbox", "text": "Sandbox"}]},
	  {"key": "UnitCap", "label": "Unit Cap", "default": 2, "values": ["125", "250", "500"]}],
	  "teamOptions": [], "AIOpts": [{"key": "CheatMult", "label": "Cheat", "default": 1, "values": [1.5, 2]}]},
	 "ai": [{"key": "adaptive", "name": "<LOC z>AI: Adaptive", "rating": 600}],
	 "map": [{"key": "automex", "label": "mexes", "default": 1, "values": [{"key": 1, "text": "enabled"}]}]}`)
	s, err := parseSettings(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Options) != 3 || s.Options[0].Default != "demoralization" || s.Options[0].Label != "Victory Condition" || s.Options[0].Values[0].Text != "Assassination" {
		t.Fatalf("options %+v", s.Options)
	}
	if s.Options[1].Default != "250" || len(s.Options[1].Values) != 3 || s.Options[2].Group != "ai" || s.Options[2].Default != 1.5 {
		t.Fatalf("plain values: %+v / %+v", s.Options[1], s.Options[2])
	}
	if len(s.AI) != 1 || s.AI[0].Name != "AI: Adaptive" || len(s.MapOptions) != 1 || s.MapOptions[0].Default != float64(1) {
		t.Fatalf("ai %+v map %+v", s.AI, s.MapOptions)
	}
}
