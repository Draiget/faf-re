package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetricsWindow(t *testing.T) {
	h := &metricsHistory{}
	start := time.Unix(1_800_000_000, 0)
	for i := 0; i < 2000; i++ { // over an hour of 2 s samples: the oldest go
		s := metricSample{t: start.Unix() + int64(2*i), cpu: float64(i % 100), memUsed: 1000 + i,
			links: map[string][2]float64{"eno1": {1, 2}}, nodes: map[int][2]float64{0: {50, 9000}}, lobbies: map[string][2]float64{}}
		if i >= 1995 { // a lobby that started at the last 5 samples
			s.lobbies["l3"] = [2]float64{0.4, 300}
		}
		h.add(s)
	}
	if n := len(h.samples); n != 1801 {
		t.Fatalf("kept %d samples, want an hour's 1801", n)
	}
	now := start.Add(2 * 1999 * time.Second)
	v := h.window(20, now)
	if len(v.T) != 11 || v.T[10] != now.Unix() || v.MemUsedMB[10] != 2999 || len(v.CPU) != 11 {
		t.Fatalf("window: %d samples, last %v", len(v.T), v.T)
	}
	l3 := v.Lobbies["l3"]
	if len(l3.CPUCores) != 11 || l3.CPUCores[0] != nil || l3.CPUCores[10] == nil || *l3.RSSMB[10] != 300 {
		t.Fatalf("lobby series %+v", l3)
	}
	if n := v.Nodes["0"]; len(n.CPU) != 11 || *n.MemFree[0] != 9000 {
		t.Fatalf("node series %+v", n)
	}
	if v.Net["eno1"].Out[3] == nil || *v.Net["eno1"].Out[3] != 2 {
		t.Fatalf("link series %+v", v.Net)
	}
	data, _ := json.Marshal(v)
	if !strings.Contains(string(data), `"cpu_cores":[null,null,null,null,null,null,0.4`) || !strings.Contains(string(data), `"interval_seconds":2`) {
		t.Fatalf("JSON %s", data)
	}

	// A sample of the manager: its running lobbies' use.
	m := testManager(t)
	m.lobbies["l1"] = &Lobby{ID: "l1", State: "game", Usage: procUsage{CPUCores: 0.7, RSSMB: 250}}
	m.lobbies["l2"] = &Lobby{ID: "l2", State: "ended"}
	s := m.sampleMetrics(now)
	if s.lobbies["l1"] != [2]float64{0.7, 250} || len(s.lobbies) != 1 || len(s.nodes) != 1 {
		t.Fatalf("sample %+v", s)
	}
}

func TestHostLogRing(t *testing.T) {
	r := &logRing{}
	ch, done := r.subscribe()
	fmt.Fprint(r, "first line\nsecond ")
	fmt.Fprint(r, "line\r\n")
	if got := r.tail(5); len(got) != 2 || got[1] != "second line" {
		t.Fatalf("tail %q", got)
	}
	if got := <-ch; got != "first line" {
		t.Fatalf("streamed %q", got)
	}
	done()
	for i := 0; i < hostLogLines+10; i++ {
		fmt.Fprintf(r, "line %d\n", i)
	}
	if got := r.tail(1_000_000); len(got) != hostLogLines || got[len(got)-1] != fmt.Sprintf("line %d", hostLogLines+9) {
		t.Fatalf("kept %d, last %q", len(got), got[len(got)-1])
	}
}

func TestLobbyLogRoutes(t *testing.T) {
	m := testManager(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "server.log")
	var b strings.Builder
	for i := 1; i <= 700; i++ {
		fmt.Fprintf(&b, "server line %d\n", i)
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	m.lobbies["l1"] = &Lobby{ID: "l1", State: "ended", Dir: dir}
	ring := &logRing{}
	fmt.Fprintln(ring, "2026/11/12 12:00:00 lobby l1: started")
	a := &api{token: "0123456789abcdef0123", m: m, maps: m.maps, procDir: t.TempDir(), hostName: "h", hostLog: ring}
	do := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+a.token)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	var resp struct {
		Lines []string `json:"lines"`
		State string   `json:"state"`
	}
	w := do("/api/v1/lobbies/l1/log?lines=3")
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Lines) != 3 || resp.Lines[2] != "server line 700" || resp.State != "ended" {
		t.Fatalf("log tail: %d %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(do("/api/v1/lobbies/l1/log").Body.Bytes(), &resp); err != nil || len(resp.Lines) != 500 || resp.Lines[0] != "server line 201" {
		t.Fatalf("default tail: %d lines", len(resp.Lines))
	}
	if w := do("/api/v1/lobbies/l9/log"); w.Code != http.StatusNotFound {
		t.Fatalf("an unknown lobby's log: %d", w.Code)
	}
	if err := json.Unmarshal(do("/api/v1/logs/host?lines=10").Body.Bytes(), &resp); err != nil || len(resp.Lines) != 1 || !strings.Contains(resp.Lines[0], "lobby l1") {
		t.Fatalf("host log %+v", resp)
	}
	// An ended lobby's stream ends at once.
	if w := do("/api/v1/lobbies/l1/log/stream"); w.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(w.Body.String(), "event: end") ||
		strings.Contains(w.Body.String(), "server line 700") {
		t.Fatalf("stream of an ended lobby: %s", w.Body)
	}
	// A running lobby's stream sends the lines written after it opened, then ends with the lobby.
	m.mu.Lock()
	m.lobbies["l1"].State = "lobby"
	m.mu.Unlock()
	go func() {
		time.Sleep(700 * time.Millisecond)
		f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
		fmt.Fprint(f, "new line\npartial")
		f.Close()
		time.Sleep(700 * time.Millisecond)
		m.mu.Lock()
		m.lobbies["l1"].State = "ended"
		m.mu.Unlock()
	}()
	w = do("/api/v1/lobbies/l1/log/stream")
	body := w.Body.String()
	if !strings.Contains(body, "data: new line\n\n") || !strings.Contains(body, "data: partial\n\n") || !strings.HasSuffix(body, "event: end\ndata: {}\n\n") ||
		strings.Contains(body, "server line") {
		t.Fatalf("stream of a running lobby: %q", body)
	}
}
