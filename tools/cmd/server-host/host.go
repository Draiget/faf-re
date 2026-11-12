package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// cpuTimes is one /proc/stat line's counters: all of them, and the idle part (idle + iowait).
type cpuTimes struct{ total, idle uint64 }

// parseProcStat reads the per-CPU lines ("cpu0 ...", not the "cpu " sum) of /proc/stat.
func parseProcStat(r io.Reader) map[int]cpuTimes {
	out := map[int]cpuTimes{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
			continue
		}
		id, err := strconv.Atoi(f[0][3:])
		if err != nil {
			continue
		}
		var t cpuTimes
		for i, s := range f[1:] {
			v, _ := strconv.ParseUint(s, 10, 64)
			if i >= 8 { // guest and guest_nice are already counted in user and nice
				break
			}
			t.total += v
			if i == 3 || i == 4 { // idle, iowait
				t.idle += v
			}
		}
		out[id] = t
	}
	return out
}

// busyPercent is how busy a CPU was between two samples, 0..100.
func busyPercent(a, b cpuTimes) float64 {
	if b.total <= a.total {
		return 0
	}
	dt := float64(b.total - a.total)
	di := float64(b.idle - a.idle)
	if di > dt {
		di = dt
	}
	return 100 * (dt - di) / dt
}

// CPU is one logical CPU as the API reports it.
type CPU struct {
	ID      int      `json:"id"`
	Core    int      `json:"core"`
	Socket  int      `json:"socket"`
	Node    int      `json:"node"` // plan WP17.16: its NUMA node
	Load    float64  `json:"load"`
	Load10  float64  `json:"load10"`
	Lobbies []string `json:"lobbies"`
}

// sampler keeps each CPU's load over the last second and the last ten, from /proc/stat once a second.
type sampler struct {
	mu      sync.Mutex
	statDir string // "/proc" normally; tests point it elsewhere
	sysDir  string // "/sys/devices/system/cpu"
	last    map[int]cpuTimes
	history map[int][]float64 // newest last, at most 10
	topo    map[int][2]int    // core, socket
}

func newSampler(procDir, sysCPUDir string) *sampler {
	return &sampler{statDir: procDir, sysDir: sysCPUDir, history: map[int][]float64{}, topo: map[int][2]int{}}
}

func readInt(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return v, err == nil
}

func (s *sampler) sample() {
	f, err := os.Open(filepath.Join(s.statDir, "stat"))
	if err != nil {
		return
	}
	now := parseProcStat(f)
	f.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, t := range now {
		if _, ok := s.topo[id]; !ok {
			core, okc := readInt(filepath.Join(s.sysDir, "cpu"+strconv.Itoa(id), "topology", "core_id"))
			sock, oks := readInt(filepath.Join(s.sysDir, "cpu"+strconv.Itoa(id), "topology", "physical_package_id"))
			if !okc {
				core = id
			}
			if !oks {
				sock = 0
			}
			s.topo[id] = [2]int{core, sock}
		}
		if prev, ok := s.last[id]; ok {
			h := append(s.history[id], busyPercent(prev, t))
			if len(h) > 10 {
				h = h[len(h)-10:]
			}
			s.history[id] = h
		}
	}
	s.last = now
}

func (s *sampler) run(stop <-chan struct{}) {
	s.sample()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.sample()
		}
	}
}

// cpus lists every CPU seen, by id, with its loads (rounded to 0.1).
func (s *sampler) cpus() []CPU {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CPU, 0, len(s.last))
	for id := range s.last {
		c := CPU{ID: id, Core: s.topo[id][0], Socket: s.topo[id][1], Lobbies: []string{}}
		if h := s.history[id]; len(h) > 0 {
			c.Load = round1(h[len(h)-1])
			sum := 0.0
			for _, v := range h {
				sum += v
			}
			c.Load10 = round1(sum / float64(len(h)))
		}
		out = append(out, c)
	}
	sortCPUs(out)
	return out
}

func sortCPUs(c []CPU) {
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j].ID < c[j-1].ID; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// memoryMB reads MemTotal and MemAvailable from /proc/meminfo.
func memoryMB(procDir string) (total, available int) {
	f, err := os.Open(filepath.Join(procDir, "meminfo"))
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 2 {
			continue
		}
		kb, _ := strconv.Atoi(fl[1])
		switch fl[0] {
		case "MemTotal:":
			total = kb / 1024
		case "MemAvailable:":
			available = kb / 1024
		}
	}
	return
}

// cpuModel is the first "model name" of /proc/cpuinfo.
func cpuModel(procDir string) string {
	f, err := os.Open(filepath.Join(procDir, "cpuinfo"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && strings.TrimSpace(k) == "model name" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
