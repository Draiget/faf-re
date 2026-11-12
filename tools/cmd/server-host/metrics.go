package main

import (
	"sort"
	"strconv"
	"sync"
	"time"
)

// Metrics history: the host samples itself every 2 s and keeps an hour: overall CPU, memory, each link, each NUMA node
// and each running lobby's server. GET /api/v1/metrics answers a window of it as columns, one value per sample time;
// a link, node or lobby absent at a sample has null there.

const (
	metricsInterval = 2 * time.Second
	metricsKeep     = time.Hour
)

type metricSample struct {
	t       int64
	cpu     float64
	memUsed int
	links   map[string][2]float64 // in, out KB/s
	nodes   map[int][2]float64    // CPU %, memory free MB
	lobbies map[string][2]float64 // CPU cores, RSS MB
}

type metricsHistory struct {
	mu      sync.Mutex
	samples []metricSample // oldest first
}

func (h *metricsHistory) add(s metricSample) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.samples = append(h.samples, s)
	cut := 0
	for cut < len(h.samples) && s.t-h.samples[cut].t > int64(metricsKeep/time.Second) {
		cut++
	}
	if cut > 0 {
		h.samples = append(h.samples[:0:0], h.samples[cut:]...)
	}
}

// LinkSeries is one link's rates over the window.
type LinkSeries struct {
	In  []*float64 `json:"in_kbps"`
	Out []*float64 `json:"out_kbps"`
}

// NodeSeries is one NUMA node's CPU load (%) and free memory over the window.
type NodeSeries struct {
	CPU     []*float64 `json:"cpu"`
	MemFree []*float64 `json:"mem_free_mb"`
}

// LobbySeries is one lobby's server: CPU (in cores) and memory over the window.
type LobbySeries struct {
	CPUCores []*float64 `json:"cpu_cores"`
	RSSMB    []*float64 `json:"rss_mb"`
}

// MetricsView is GET /api/v1/metrics's answer.
type MetricsView struct {
	OK        bool                   `json:"ok"`
	Interval  int                    `json:"interval_seconds"`
	T         []int64                `json:"t"`
	CPU       []float64              `json:"cpu"`
	MemUsedMB []int                  `json:"mem_used_mb"`
	Net       map[string]LinkSeries  `json:"net"`
	Nodes     map[string]NodeSeries  `json:"nodes"`
	Lobbies   map[string]LobbySeries `json:"lobbies"`
}

func ptr(v float64) *float64 { return &v }

// window answers the samples of the last `seconds` before now.
func (h *metricsHistory) window(seconds int, now time.Time) MetricsView {
	h.mu.Lock()
	var in []metricSample
	for _, s := range h.samples {
		if now.Unix()-s.t <= int64(seconds) {
			in = append(in, s)
		}
	}
	h.mu.Unlock()
	v := MetricsView{OK: true, Interval: int(metricsInterval / time.Second), T: make([]int64, len(in)), CPU: make([]float64, len(in)),
		MemUsedMB: make([]int, len(in)), Net: map[string]LinkSeries{}, Nodes: map[string]NodeSeries{}, Lobbies: map[string]LobbySeries{}}
	for i, s := range in {
		v.T[i], v.CPU[i], v.MemUsedMB[i] = s.t, s.cpu, s.memUsed
		for name, val := range s.links {
			ls, ok := v.Net[name]
			if !ok {
				ls = LinkSeries{In: make([]*float64, len(in)), Out: make([]*float64, len(in))}
			}
			ls.In[i], ls.Out[i] = ptr(val[0]), ptr(val[1])
			v.Net[name] = ls
		}
		for id, val := range s.nodes {
			key := strconv.Itoa(id)
			ns, ok := v.Nodes[key]
			if !ok {
				ns = NodeSeries{CPU: make([]*float64, len(in)), MemFree: make([]*float64, len(in))}
			}
			ns.CPU[i], ns.MemFree[i] = ptr(val[0]), ptr(val[1])
			v.Nodes[key] = ns
		}
		for id, val := range s.lobbies {
			lsr, ok := v.Lobbies[id]
			if !ok {
				lsr = LobbySeries{CPUCores: make([]*float64, len(in)), RSSMB: make([]*float64, len(in))}
			}
			lsr.CPUCores[i], lsr.RSSMB[i] = ptr(val[0]), ptr(val[1])
			v.Lobbies[id] = lsr
		}
	}
	return v
}

// sampleMetrics takes one sample of the machine and the running lobbies.
func (m *manager) sampleMetrics(now time.Time) metricSample {
	cpus := m.cpus()
	s := metricSample{t: now.Unix(), links: map[string][2]float64{}, nodes: map[int][2]float64{}, lobbies: map[string][2]float64{}}
	load := map[int]float64{}
	sum := 0.0
	for _, c := range cpus {
		load[c.ID] = c.Load
		sum += c.Load
	}
	if len(cpus) > 0 {
		s.cpu = round1(sum / float64(len(cpus)))
	}
	total, avail := memoryMB(m.procDir)
	s.memUsed = total - avail
	for _, l := range m.links() {
		s.links[l.Name] = [2]float64{l.InKBps, l.OutKBps}
	}
	for _, n := range m.nodes() {
		nsum, count := 0.0, 0
		for _, c := range n.CPUs {
			if v, ok := load[c]; ok {
				nsum += v
				count++
			}
		}
		avg := 0.0
		if count > 0 {
			avg = round1(nsum / float64(count))
		}
		s.nodes[n.ID] = [2]float64{avg, float64(n.MemoryMB.Free)}
	}
	m.mu.Lock()
	ids := make([]string, 0, len(m.lobbies))
	for id, l := range m.lobbies {
		if running(l.State) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		u := m.lobbies[id].Usage
		s.lobbies[id] = [2]float64{u.CPUCores, float64(u.RSSMB)}
	}
	m.mu.Unlock()
	return s
}

// runMetrics samples every 2 s until stop.
func (m *manager) runMetrics(h *metricsHistory, stop <-chan struct{}) {
	t := time.NewTicker(metricsInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			h.add(m.sampleMetrics(now))
		}
	}
}
