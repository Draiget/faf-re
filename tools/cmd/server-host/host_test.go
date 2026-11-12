package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const setonsScenario = `version = 3
ScenarioInfo = {
    name = "Seton's Clutch",
    description = "<LOC SCMP_009_Description>Dozens of battles.",
    type = 'skirmish',
    size = {1024, 1024},
    map = '/maps/SCMP_009/SCMP_009.scmap',
    Configurations = {
        ['standard'] = {
            teams = {
                { name = 'FFA', armies = {'ARMY_1','ARMY_2','ARMY_3','ARMY_4','ARMY_5','ARMY_6','ARMY_7','ARMY_8',} },
            },
            customprops = {},
        },
    }}
`

func TestParseScenario(t *testing.T) {
	name, desc, size, players, ok := parseScenario(setonsScenario)
	if !ok || name != "Seton's Clutch" || desc != "Dozens of battles." || size != [2]int{1024, 1024} || players != 8 {
		t.Fatalf("got %q %q %v %d %v", name, desc, size, players, ok)
	}
	if _, _, _, _, ok := parseScenario(strings.Replace(setonsScenario, "'skirmish'", "'campaign_coop'", 1)); ok {
		t.Fatal("a non-skirmish map was listed")
	}
	for in, want := range map[int]int{256: 5, 512: 10, 1024: 20, 2048: 40, 4096: 81} {
		if got := kmOf([2]int{in, in}); got != want {
			t.Errorf("kmOf(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestScanMaps(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "SCMP_009"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SCMP_009", "SCMP_009_scenario.lua"), []byte(setonsScenario), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(dir, "empty"), 0o755)
	got := scanMaps([]mapDir{{"fa", dir}, {"missing", filepath.Join(dir, "nope")}})
	if len(got) != 1 || got[0].ID != "scmp_009" || got[0].File != "/maps/SCMP_009/SCMP_009_scenario.lua" || got[0].KM != 20 || got[0].Source != "fa" {
		t.Fatalf("got %+v", got)
	}
}

func TestProcStat(t *testing.T) {
	a := parseProcStat(strings.NewReader("cpu  10 0 10 80 0 0 0 0 0 0\ncpu0 100 0 100 800 0 0 0 0 0 0\ncpu1 0 0 0 1000 0 0 0 0 0 0\nintr 5\n"))
	b := parseProcStat(strings.NewReader("cpu0 150 0 150 900 0 0 0 0 0 0\ncpu1 0 0 0 1100 0 0 0 0 0 0\n"))
	if len(a) != 2 {
		t.Fatalf("cpus %v", a)
	}
	if got := busyPercent(a[0], b[0]); got != 50 {
		t.Errorf("cpu0 %v, want 50", got)
	}
	if got := busyPercent(a[1], b[1]); got != 0 {
		t.Errorf("cpu1 %v, want 0", got)
	}
}

func TestHint(t *testing.T) {
	h := hintFor(2, 10)
	if h.MeanCores != 0.066 || h.WorstCores != 0.144 || h.SuggestedCores != 1 {
		t.Fatalf("1v1 10 km: %+v", h)
	}
	if h.MinConnectionKBps != 165 || h.ServerUploadKBps != 205 || h.MaxPlayers != 16 {
		t.Fatalf("1v1 minimums: %+v", h)
	}
	if m := hintFor(8, 20); m.MinConnectionKBps != 360 || m.ServerUploadKBps != 2300 {
		t.Fatalf("8 players minimums: %+v", m)
	}
	if m := hintFor(16, 40); m.MinConnectionKBps != 360 || m.ServerUploadKBps != 2600 {
		t.Fatalf("16 players minimums: %+v", m)
	}
	h = hintFor(12, 81)
	if h.WorstCores != 1.002 || h.SuggestedCores != 2 || !strings.Contains(h.Basis, "estimate") {
		t.Fatalf("12 players 81 km: %+v", h)
	}
}

func TestPickCPUs(t *testing.T) {
	cpus := []CPU{{ID: 0, Load10: 5}, {ID: 1, Load10: 90}, {ID: 2, Load10: 1, Lobbies: []string{"l1"}}, {ID: 3, Load10: 30}}
	if got := pickCPUs(cpus, 2); len(got) != 2 || got[0] != 0 || got[1] != 3 {
		t.Fatalf("got %v, want [0 3]: free CPUs first, least loaded", got)
	}
	if got := pickCPUs(cpus, 9); len(got) != 4 {
		t.Fatalf("got %v", got)
	}
}

func testManager(t *testing.T) *manager {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "maps", "SCMP_009"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "maps", "SCMP_009", "SCMP_009_scenario.lua"), []byte(setonsScenario), 0o644)
	maps := scanMaps([]mapDir{{"fa", filepath.Join(dir, "maps")}})
	return newManager(config{runsDir: filepath.Join(dir, "runs"), publicHost: "203.0.113.5", listenIP: "127.0.0.1", portFirst: 27200, portLast: 27210, maxLobbies: 2},
		func() []Map { return maps }, func() []CPU { return []CPU{{ID: 0}, {ID: 1}} })
}

func TestValidateAndMatchFile(t *testing.T) {
	m := testManager(t)
	req := CreateRequest{Map: "SCMP_009", Seats: []Seat{{Kind: "human", Name: "O'Neil"}, {Kind: "ai", AI: "rush", Faction: 2, Team: 3}, {Kind: "human", Faction: 5}}}
	mp, err := m.validate(&req)
	if err != nil {
		t.Fatal(err)
	}
	if req.Seats[0].UID != 1001 || req.Seats[2].UID != 1002 || req.Seats[1].Name != "AI: rush" || req.Control != "player" {
		t.Fatalf("seats %+v control %q", req.Seats, req.Control)
	}
	if f := req.Seats[2].Faction; f < 1 || f > 4 {
		t.Fatalf("random faction not resolved: %d", f)
	}
	l := &Lobby{ID: "l1", Name: "test", Control: req.Control, Seats: req.Seats, Options: map[string]string{"Victory": "sandbox"}}
	text := matchFile(l, mp.File)
	for _, want := range []string{"MatchLobbyControl = 'player'", "['1001'] = '" + req.Seats[0].token + "'", "ScenarioFile = '/maps/SCMP_009/SCMP_009_scenario.lua'",
		"Victory = 'sandbox'", "PlayerName = 'O\\'Neil'", "AIPersonality = 'rush'", "StartSpot = 3"} {
		if !strings.Contains(text, want) {
			t.Errorf("match file lacks %q:\n%s", want, text)
		}
	}
	for _, bad := range []CreateRequest{
		{Map: "nope", Seats: []Seat{{Kind: "human"}}},
		{Map: "scmp_009", Seats: []Seat{{Kind: "ai"}}},
		{Map: "scmp_009", Seats: make([]Seat, 9)},
		{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}, Options: map[string]string{"ScenarioFile": "/x"}},
		{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}, Options: map[string]string{"bad key": "1"}},
		{Map: "scmp_009", Seats: []Seat{{Kind: "ai", AI: "nobody"}, {Kind: "human"}}},
		{Map: "scmp_009", Seats: []Seat{{Kind: "human", UID: 5}, {Kind: "human", UID: 5}}},
		{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}, Control: "anyone"},
	} {
		b := bad
		if _, err := m.validate(&b); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestObservers(t *testing.T) {
	m := testManager(t)
	req := CreateRequest{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}, Observers: []Observer{{Name: "Caster"}, {Referee: true}}, ObserverDelay: 120}
	mp, err := m.validate(&req)
	if err != nil {
		t.Fatal(err)
	}
	if req.Observers[1].Name != "Observer 2" || req.Observers[0].token == "" || req.Observers[0].token == req.Observers[1].token {
		t.Fatalf("observers %+v", req.Observers)
	}
	l := &Lobby{ID: "l1", Control: "organiser", Seats: req.Seats, Observers: req.Observers, ObserverDelay: req.ObserverDelay, Hint: hintFor(1, 20)}
	text := matchFile(l, mp.File)
	for _, want := range []string{"MatchObservers = { '" + req.Observers[0].token + "' }", "MatchReferees = { '" + req.Observers[1].token + "' }",
		"MatchRules = { MinConnectionKBps = 165, ObserverDelaySeconds = 120 }"} {
		if !strings.Contains(text, want) {
			t.Errorf("match file lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(matchFile(&Lobby{ID: "l2", Control: "player", Seats: req.Seats}, mp.File), "MatchObservers") {
		t.Error("observers written for a lobby without any")
	}
	for _, bad := range []CreateRequest{
		{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}, ObserverDelay: -1},
		{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}, Observers: make([]Observer, 33)},
	} {
		b := bad
		if _, err := m.validate(&b); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestAPIAuthAndRoutes(t *testing.T) {
	m := testManager(t)
	a := &api{token: "0123456789abcdef0123", corsOrigin: "http://localhost:5173", m: m, maps: m.maps, procDir: t.TempDir(), hostName: "h"}
	do := func(method, path, token, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "/api/v1/host", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do("GET", "/api/v1/host", "0123456789abcdef0124", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", w.Code)
	}
	if w := do("OPTIONS", "/api/v1/lobbies", "", "http://localhost:5173"); w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}
	if w := do("GET", "/api/v1/host", "0123456789abcdef0123", "http://evil.example"); w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS for another origin")
	}
	w := do("GET", "/api/v1/host", "0123456789abcdef0123", "")
	var host struct {
		OK   bool `json:"ok"`
		Host struct {
			CPUs    []CPU    `json:"cpus"`
			AI      []string `json:"ai"`
			Lobbies int      `json:"lobbies"`
		} `json:"host"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &host); err != nil || !host.OK || len(host.Host.CPUs) != 2 || len(host.Host.AI) == 0 || host.Host.Lobbies != 0 {
		t.Fatalf("host: %s", w.Body)
	}
	if w := do("GET", "/api/v1/maps", "0123456789abcdef0123", ""); !strings.Contains(w.Body.String(), `"players":8`) {
		t.Fatalf("maps: %s", w.Body)
	}
	if w := do("GET", "/api/v1/hint?players=8&km=20", "0123456789abcdef0123", ""); !strings.Contains(w.Body.String(), `"suggested_cores":1`) {
		t.Fatalf("hint: %s", w.Body)
	}
	if w := do("GET", "/api/v1/lobbies/l9/api/v1/status", "0123456789abcdef0123", ""); w.Code != http.StatusNotFound {
		t.Fatalf("proxy to no lobby: %d", w.Code)
	}
}
