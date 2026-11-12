package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Plan WP17.16: the machine as placement sees it: NUMA nodes with their CPUs and memory, and network links.

// Node is one NUMA node.
type Node struct {
	ID       int   `json:"id"`
	CPUs     []int `json:"cpus"`
	MemoryMB struct {
		Total int `json:"total"`
		Free  int `json:"free"` // MemFree + the node's inactive file pages (what it can give without swapping)
	} `json:"memory_mb"`
}

// Link is one physical network link.
type Link struct {
	Name      string  `json:"name"`
	SpeedMbps int     `json:"speed_mbps"`
	InKBps    float64 `json:"in_kbps"`
	OutKBps   float64 `json:"out_kbps"`
}

// parseCPUList reads the kernel's "0,2,4-7" form.
func parseCPUList(text string) []int {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(text), ",") {
		if part == "" {
			continue
		}
		first, last, ranged := strings.Cut(part, "-")
		a, err1 := strconv.Atoi(first)
		b := a
		var err2 error
		if ranged {
			b, err2 = strconv.Atoi(last)
		}
		if err1 != nil || err2 != nil || b < a {
			continue
		}
		for c := a; c <= b; c++ {
			out = append(out, c)
		}
	}
	return out
}

// nodeMeminfoKB reads "Node N MemTotal: 123 kB" lines into name -> kB.
func nodeMeminfoKB(text string) map[string]int {
	out := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == "Node" {
			v, _ := strconv.Atoi(f[3])
			out[strings.TrimSuffix(f[2], ":")] = v
		}
	}
	return out
}

// readNodes lists the NUMA nodes under sysDir (/sys/devices/system/node); one node with every CPU when there are none.
func readNodes(sysDir string, allCPUs []int) []Node {
	dirs, _ := filepath.Glob(filepath.Join(sysDir, "node[0-9]*"))
	var nodes []Node
	for _, d := range dirs {
		id, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(d), "node"))
		if err != nil {
			continue
		}
		list, err := os.ReadFile(filepath.Join(d, "cpulist"))
		if err != nil {
			continue
		}
		n := Node{ID: id, CPUs: parseCPUList(string(list))}
		if mem, err := os.ReadFile(filepath.Join(d, "meminfo")); err == nil {
			kb := nodeMeminfoKB(string(mem))
			n.MemoryMB.Total = kb["MemTotal"] / 1024
			n.MemoryMB.Free = (kb["MemFree"] + kb["Inactive(file)"]) / 1024
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		nodes = []Node{{ID: 0, CPUs: append([]int(nil), allCPUs...)}}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return nodes
}

// linkSampler keeps each physical link's speed and its in/out rate over the last second.
type linkSampler struct {
	mu    sync.Mutex
	dir   string // /sys/class/net
	last  map[string][2]uint64
	at    time.Time
	links []Link
}

func (s *linkSampler) sample() {
	entries, _ := os.ReadDir(s.dir)
	now := time.Now()
	cur := map[string][2]uint64{}
	var links []Link
	for _, e := range entries {
		name := e.Name()
		base := filepath.Join(s.dir, name)
		// Physical links only: a "device" link; bridges, veths, docker and bonding masters have none or no speed.
		if _, err := os.Stat(filepath.Join(base, "device")); err != nil {
			continue
		}
		state, _ := os.ReadFile(filepath.Join(base, "operstate"))
		if strings.TrimSpace(string(state)) != "up" {
			continue
		}
		speed, ok := readInt(filepath.Join(base, "speed"))
		if !ok || speed <= 0 {
			continue
		}
		rx, _ := readInt(filepath.Join(base, "statistics", "rx_bytes"))
		tx, _ := readInt(filepath.Join(base, "statistics", "tx_bytes"))
		cur[name] = [2]uint64{uint64(rx), uint64(tx)}
		l := Link{Name: name, SpeedMbps: speed}
		if prev, ok := s.last[name]; ok && !s.at.IsZero() {
			dt := now.Sub(s.at).Seconds()
			if dt > 0 && cur[name][0] >= prev[0] && cur[name][1] >= prev[1] {
				l.InKBps = round1(float64(cur[name][0]-prev[0]) / 1024 / dt)
				l.OutKBps = round1(float64(cur[name][1]-prev[1]) / 1024 / dt)
			}
		}
		links = append(links, l)
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Name < links[j].Name })
	s.mu.Lock()
	s.last, s.at, s.links = cur, now, links
	s.mu.Unlock()
}

func (s *linkSampler) get() []Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Link(nil), s.links...)
}

// procUsage is a lobby's server process as the kernel counts it: CPU (in cores, over the last sample) and memory.
type procUsage struct {
	CPUCores float64 `json:"cpu_cores"`
	RSSMB    int     `json:"rss_mb"`
}

// procTicks reads utime+stime (clock ticks) and RSS (kB) of a process from /proc.
func procTicks(procDir string, pid int) (ticks uint64, rssKB int, ok bool) {
	stat, err := os.ReadFile(filepath.Join(procDir, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, 0, false
	}
	text := string(stat)
	end := strings.LastIndexByte(text, ')') // the command can hold spaces and parentheses
	if end < 0 {
		return 0, 0, false
	}
	f := strings.Fields(text[end+1:])
	if len(f) < 13 {
		return 0, 0, false
	}
	u, _ := strconv.ParseUint(f[11], 10, 64) // field 14 utime
	s, _ := strconv.ParseUint(f[12], 10, 64) // field 15 stime
	if status, err := os.ReadFile(filepath.Join(procDir, strconv.Itoa(pid), "status")); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if v, found := strings.CutPrefix(line, "VmRSS:"); found {
				rssKB, _ = strconv.Atoi(strings.Fields(v)[0])
			}
		}
	}
	return u + s, rssKB, true
}
