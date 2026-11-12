package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMain turns the test binary into a stand-in lobby server when the host starts it as one: it waits to be
// stopped, as the real server waits in its lobby.
func TestMain(m *testing.M) {
	if os.Getenv("SERVER_HOST_FAKE_SERVER") == "1" {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		select {
		case <-sig:
		case <-time.After(60 * time.Second):
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// poolManager is testManager on the two-node machine of the placement tests.
func poolManager(t *testing.T) *manager {
	m := testManager(t)
	m.cfg.maxLobbies = 3
	tm := twoNodeMachine()
	m.cpus = func() []CPU { return append([]CPU(nil), tm.cpus...) }
	m.nodes = func() []Node { return tm.nodes }
	return m
}

func boolp(v bool) *bool { return &v }
func intp(v int) *int    { return &v }

func TestPoolSettingsAndSides(t *testing.T) {
	m := poolManager(t)
	m.poolFile = filepath.Join(t.TempDir(), "pool.json")
	if _, err := m.updatePool(PoolUpdate{Enabled: boolp(true)}); err == nil {
		t.Fatal("player hosting turned on without CPUs")
	}
	access := "code"
	for _, bad := range []PoolUpdate{{CPUs: &[]int{99}}, {Nodes: &[]int{7}}, {MaxGames: intp(0)}, {MaxPlayers: intp(17)}, {Cores: intp(-1)},
		{Access: &access, Code: new(string), MaxQueue: intp(-1)}, {Options: &map[string]any{"ScenarioFile": "/x"}}, {CPUs: &[]int{1, 1}}} {
		if _, err := m.updatePool(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if p, _ := m.poolView(); p.Enabled || len(p.CPUs) != 0 {
		t.Fatalf("a refused update changed the pool: %+v", p)
	}
	// Node 1 (the odd CPUs) for the players.
	warnings, err := m.updatePool(PoolUpdate{Enabled: boolp(true), Nodes: &[]int{1}, MaxGames: intp(2), Cores: intp(1), Access: &access})
	if err != nil {
		t.Fatal(err)
	}
	p, u := m.poolView()
	if len(p.CPUs) != 8 || p.CPUs[0] != 1 || len(p.Nodes) != 1 || p.Nodes[0] != 1 || len(p.Code) != 8 || u.FreeCores != 4 || len(warnings) != 0 {
		t.Fatalf("pool %+v usage %+v warnings %v", p, u, warnings)
	}
	// Auto for the operator stays off the pool; the pool's plan stays on it.
	if pl := m.planOn("operator", PlanRequest{Players: 8, KM: 20, Cores: 3}); len(pl.Nodes) != 1 || pl.Nodes[0] != 0 || !pl.Fits {
		t.Fatalf("operator plan %+v", pl)
	}
	if pl := m.planOn("pool", PlanRequest{Players: 8, KM: 20}); len(pl.Nodes) != 1 || pl.Nodes[0] != 1 || pl.Cores != 1 {
		t.Fatalf("pool plan %+v", pl)
	}
	if pl := m.planOn("operator", PlanRequest{Players: 2, KM: 10, CPUs: []int{3}}); !strings.Contains(codes(pl), "pool_overlap") {
		t.Fatalf("operator by hand on the pool: %s", codes(pl))
	}
	if pl := m.planOn("pool", PlanRequest{Players: 2, KM: 10, CPUs: []int{2}}); !strings.Contains(codes(pl), "outside_pool") {
		t.Fatalf("pool by hand off the pool: %s", codes(pl))
	}
	// Five cores on the pool's node: four whole cores, then a sibling.
	if pl := m.planOn("pool", PlanRequest{Players: 8, KM: 20, Cores: 5}); len(pl.CPUs) != 5 || !strings.Contains(codes(pl), "node_short") {
		t.Fatalf("pool plan of 5: %+v %s", pl, codes(pl))
	}
	if pl := m.planOn("pool", PlanRequest{Players: 8, KM: 20, Cores: 9}); pl.Fits || !strings.Contains(codes(pl), "machine_short") {
		t.Fatalf("pool plan of 9 on 8 CPUs: %s", codes(pl))
	}
	// Kept for the next run.
	m2 := poolManager(t)
	m2.poolFile = m.poolFile
	m2.loadPool()
	if p2, _ := m2.poolView(); !p2.Enabled || len(p2.CPUs) != 8 || p2.Code != p.Code {
		t.Fatalf("kept pool %+v", p2)
	}
	// Off with nothing queued: the operator's Auto may use every CPU again.
	if _, err := m.updatePool(PoolUpdate{Enabled: boolp(false)}); err != nil {
		t.Fatal(err)
	}
	if mc := m.machineFor("operator"); mc.allowed != nil {
		t.Fatalf("pool off, operator still kept off it: %v", mc.allowed)
	}
}

func TestQueueOrderUpAndCancel(t *testing.T) {
	m := poolManager(t)
	m.cfg.maxLobbies = 0 // nothing fits: everything waits for a game
	req := CreateRequest{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}, Control: "organiser"}
	if _, _, code, err := m.createOrQueue(req); err == nil || code != http.StatusConflict {
		t.Fatalf("without queue: %d %v", code, err)
	}
	req.Queue = true
	var ids []string
	for i := 0; i < 3; i++ {
		l, q, code, err := m.createOrQueue(req)
		if err != nil || l != nil || q == nil || code != http.StatusAccepted {
			t.Fatalf("queue %d: %d %v %+v", i, code, err, q)
		}
		if q.Position != i+1 || q.WaitingFor != "games" || q.Side != "operator" || q.Kind != "tournament" || q.Map.ID != "scmp_009" || q.Seats != 1 {
			t.Fatalf("item %+v", q)
		}
		ids = append(ids, q.ID)
	}
	bad := req
	bad.Seats = []Seat{{Kind: "ai"}}
	if _, _, code, _ := m.createOrQueue(bad); code != http.StatusBadRequest {
		t.Fatalf("a bad lobby with queue: %d", code)
	}
	if err := m.moveUp(ids[2]); err != nil {
		t.Fatal(err)
	}
	q := m.listQueue()
	if len(q) != 3 || q[0].ID != ids[0] || q[1].ID != ids[2] || q[1].Position != 2 || q[2].Position != 3 {
		t.Fatalf("after up: %+v", q)
	}
	if err := m.moveUp(ids[0]); err != nil { // already first
		t.Fatal(err)
	}
	if err := m.cancelQueued(ids[2]); err != nil {
		t.Fatal(err)
	}
	if err := m.cancelQueued(ids[2]); err == nil {
		t.Fatal("cancelled twice")
	}
	if q := m.listQueue(); len(q) != 2 || q[1].ID != ids[1] || q[1].Position != 2 {
		t.Fatalf("after cancel: %+v", q)
	}
	if started := m.pump(); len(started) != 0 {
		t.Fatalf("started with no room: %v", started)
	}

	// Through the API.
	a := &api{token: "0123456789abcdef0123", m: m, maps: m.maps, procDir: t.TempDir(), hostName: "h"}
	do := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+a.token)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := do("POST", "/api/v1/lobbies", `{"map": "scmp_009", "seats": [{"kind": "human"}], "kind": "custom", "queue": true}`); w.Code != http.StatusAccepted ||
		!strings.Contains(w.Body.String(), `"queued":{`) || !strings.Contains(w.Body.String(), `"kind":"custom"`) {
		t.Fatalf("queued over the API: %d %s", w.Code, w.Body)
	}
	if w := do("GET", "/api/v1/queue", ""); !strings.Contains(w.Body.String(), `"waiting_for":"games"`) || strings.Count(w.Body.String(), `"id":"q`) != 3 {
		t.Fatalf("queue: %s", w.Body)
	}
	if w := do("POST", "/api/v1/queue/"+ids[1]+"/up", ""); w.Code != http.StatusOK {
		t.Fatalf("up: %d %s", w.Code, w.Body)
	}
	if w := do("DELETE", "/api/v1/queue/q99", ""); w.Code != http.StatusNotFound {
		t.Fatalf("cancel an unknown item: %d", w.Code)
	}
	if w := do("POST", "/api/v1/lobbies", `{"map": "scmp_009", "seats": [{"kind": "human"}], "kind": "league"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown kind: %d", w.Code)
	}
	for _, path := range []string{"/api/v1/slots", "/api/v1/claim/0123456789"} {
		if w := do("GET", path, ""); w.Code != http.StatusNotFound {
			t.Fatalf("%s still answers: %d", path, w.Code)
		}
	}
	// A stopping host starts nothing, from the queue or new: the queue would refill what stopAll ends.
	m.stopAll()
	m.cfg.maxLobbies = 3
	if started := m.pump(); len(started) != 0 || len(m.listQueue()) != 3 {
		t.Fatalf("pumped while stopping: %v", started)
	}
	if _, _, code, err := m.createOrQueue(CreateRequest{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}}); code != http.StatusServiceUnavailable {
		t.Fatalf("a lobby while stopping: %d %v", code, err)
	}
}

func TestPlanSideOverAPI(t *testing.T) {
	m := poolManager(t)
	if _, err := m.updatePool(PoolUpdate{Enabled: boolp(true), CPUs: &[]int{1, 3}}); err != nil {
		t.Fatal(err)
	}
	a := &api{token: "0123456789abcdef0123", m: m, maps: m.maps, procDir: t.TempDir(), hostName: "h"}
	do := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+a.token)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	var resp struct {
		Side string `json:"side"`
		Plan Plan   `json:"plan"`
	}
	w := do("POST", "/api/v1/plan", `{"players": 2, "km": 10, "side": "pool"}`)
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Side != "pool" || len(resp.Plan.CPUs) != 1 || (resp.Plan.CPUs[0] != 1 && resp.Plan.CPUs[0] != 3) {
		t.Fatalf("pool plan: %s", w.Body)
	}
	w = do("POST", "/api/v1/plan", `{"players": 2, "km": 10, "cores": 1}`)
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Side != "operator" || resp.Plan.CPUs[0] == 1 || resp.Plan.CPUs[0] == 3 {
		t.Fatalf("operator plan: %s", w.Body)
	}
	if w := do("POST", "/api/v1/plan", `{"players": 2, "km": 10, "side": "elsewhere"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown side: %d", w.Code)
	}
	if w := do("PUT", "/api/v1/pool", `{"max_games": 3, "drop_queue": true}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"max_games":3`) ||
		!strings.Contains(w.Body.String(), `"usage":{"games":0`) {
		t.Fatalf("PUT pool: %d %s", w.Code, w.Body)
	}
	if w := do("PUT", "/api/v1/pool", `{"slots": 3}`); w.Code != http.StatusBadRequest {
		t.Fatalf("PUT pool with an unknown field: %d", w.Code)
	}
}

func TestRequestChecks(t *testing.T) {
	m := poolManager(t)
	a := &api{token: "0123456789abcdef0123", m: m, maps: m.maps, procDir: t.TempDir(), hostName: "h"}
	do := func(method, path, body, ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = ip + ":40000"
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "/api/v1/public/pool", "", "198.51.100.1"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("public pool: %d %s", w.Code, w.Body)
	}
	if w := do("GET", "/api/v1/public/maps", "", "198.51.100.1"); w.Code != http.StatusForbidden {
		t.Fatalf("public maps with hosting off: %d", w.Code)
	}
	if w := do("POST", "/api/v1/public/requests", `{"player": "Ann", "map": "scmp_009"}`, "198.51.100.1"); w.Code != http.StatusForbidden {
		t.Fatalf("a request with hosting off: %d %s", w.Code, w.Body)
	}
	if w := do("GET", "/api/v1/pool", "", "198.51.100.1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("the admin pool without a token: %d", w.Code)
	}
	access := "code"
	code := "letmein1"
	if _, err := m.updatePool(PoolUpdate{Enabled: boolp(true), Nodes: &[]int{1}, MaxPlayers: intp(3), MaxQueue: intp(1), Access: &access, Code: &code,
		Options: &map[string]any{"Victory": "sandbox"}}); err != nil {
		t.Fatal(err)
	}
	m.cfg.maxLobbies = 0 // nothing starts: requests queue
	if w := do("GET", "/api/v1/public/maps", "", "198.51.100.1"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "scmp_009") {
		t.Fatalf("public maps: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/api/v1/public/requests", `{"player": "Ann", "map": "scmp_009", "code": "nope"}`, "198.51.100.2"); w.Code != http.StatusForbidden {
		t.Fatalf("a wrong code: %d %s", w.Code, w.Body)
	}
	for _, body := range []string{
		`{"player": "", "map": "scmp_009", "code": "letmein1"}`,
		`{"player": "Ann", "map": "nope", "code": "letmein1"}`,
		`{"player": "Ann", "map": "scmp_009", "code": "letmein1", "seats": [{"kind":"ai"},{"kind":"human"}]}`,
		`{"player": "Ann", "map": "scmp_009", "code": "letmein1", "seats": [{"kind":"human"},{"kind":"human"},{"kind":"human"},{"kind":"ai"}]}`,
		`{"player": "Ann", "map": "scmp_009", "code": "letmein1", "options": {"ScenarioFile": "/x"}}`,
		`{"player": "Ann", "map": "scmp_009", "code": "letmein1", "cpus": [1]}`,
	} {
		if w := do("POST", "/api/v1/public/requests", body, "198.51.100.3"); w.Code != http.StatusBadRequest {
			t.Errorf("accepted %s: %d %s", body, w.Code, w.Body)
		}
	}
	var got struct {
		OK      bool        `json:"ok"`
		Request RequestView `json:"request"`
	}
	w := do("POST", "/api/v1/public/requests", `{"player": "Ann", "map": "scmp_009", "code": "letmein1", "seats": [{"kind":"human"},{"kind":"ai","ai":"rush"}]}`, "198.51.100.4")
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !got.OK || got.Request.State != "queued" || got.Request.Position == nil || *got.Request.Position != 1 ||
		len(got.Request.Key) != 32 || got.Request.Lobby != nil {
		t.Fatalf("queued request: %d %s", w.Code, w.Body)
	}
	first := got.Request
	if w := do("POST", "/api/v1/public/requests", `{"player": "ann", "map": "scmp_009", "code": "letmein1"}`, "198.51.100.4"); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "already has a request") {
		t.Fatalf("a second live request by name and address: %d %s", w.Code, w.Body)
	}
	// The queue holds one: the next is refused, with its request.
	w = do("POST", "/api/v1/public/requests", `{"player": "Bo", "map": "scmp_009", "code": "letmein1"}`, "198.51.100.5")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"state":"refused"`) || !strings.Contains(w.Body.String(), "queue is full") {
		t.Fatalf("over max_queue: %d %s", w.Code, w.Body)
	}
	// The operator sees it in the queue.
	q := m.listQueue()
	if len(q) != 1 || q[0].Side != "pool" || q[0].Kind != "custom" || q[0].Player == nil || *q[0].Player != "Ann" || q[0].Request == nil || *q[0].Request != first.ID ||
		q[0].Seats != 2 || q[0].WaitingFor != "games" {
		t.Fatalf("pool queue %+v", q)
	}
	if opts := q[0].req.Options; opts["Victory"] != "sandbox" || q[0].req.LobbyMinutes != 60 || q[0].req.Control != "player" {
		t.Fatalf("the queued game's settings %+v", q[0].req)
	}
	// Following it needs its key.
	if w := do("GET", "/api/v1/public/requests/"+first.ID+"?key=wrong", "", "203.0.113.9"); w.Code != http.StatusNotFound {
		t.Fatalf("a wrong key: %d", w.Code)
	}
	if w := do("GET", "/api/v1/public/requests/"+first.ID+"?key="+first.Key, "", "203.0.113.9"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"position":1`) {
		t.Fatalf("follow: %d %s", w.Code, w.Body)
	}
	if w := do("DELETE", "/api/v1/public/requests/"+first.ID+"?key="+first.Key, "", "203.0.113.9"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"cancelled"`) {
		t.Fatalf("cancel: %d %s", w.Code, w.Body)
	}
	if w := do("DELETE", "/api/v1/public/requests/"+first.ID+"?key="+first.Key, "", "203.0.113.9"); w.Code != http.StatusConflict {
		t.Fatalf("cancel twice: %d %s", w.Code, w.Body)
	}
	if len(m.listQueue()) != 0 {
		t.Fatal("a cancelled request is still queued")
	}
	// Six attempts a minute from one address, whatever they were.
	for i := 0; i < 10; i++ {
		w := do("POST", "/api/v1/public/requests", `{"player": "", "map": "scmp_009", "code": "letmein1"}`, "198.51.100.6")
		if (i < requestsPerMinute) != (w.Code == http.StatusBadRequest) || (i >= requestsPerMinute && w.Code != http.StatusTooManyRequests) {
			t.Fatalf("attempt %d: %d", i+1, w.Code)
		}
	}
	// Off with drop_queue: the queued request is cancelled.
	w = do("POST", "/api/v1/public/requests", `{"player": "Cy", "map": "scmp_009", "code": "letmein1"}`, "198.51.100.7")
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Request.State != "queued" {
		t.Fatalf("queued: %s", w.Body)
	}
	if _, err := m.updatePool(PoolUpdate{Enabled: boolp(false), DropQueue: true}); err != nil {
		t.Fatal(err)
	}
	if v, err := m.getRequest(got.Request.ID, got.Request.Key); err != nil || v.State != "cancelled" || v.Reason == nil {
		t.Fatalf("after drop_queue: %+v %v", v, err)
	}
	// Ended requests are forgotten after a while.
	m.pruneRequests(time.Now().Add(requestKeep + time.Minute))
	if _, err := m.getRequest(got.Request.ID, got.Request.Key); err == nil {
		t.Fatal("an old ended request is still kept")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "198.51.100.1:5000"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	if got := clientIP(r); got != "198.51.100.1" {
		t.Fatalf("a direct client claiming another address: %s", got)
	}
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "10.9.9.9, 198.51.100.2")
	if got := clientIP(r); got != "198.51.100.2" {
		t.Fatalf("behind a local proxy: %s", got)
	}
}

func TestSeatAIsFromTheCatalog(t *testing.T) {
	m := testManager(t)
	m.settings = &settingsSource{base: &Settings{AI: []AIType{{Key: "adaptive"}, {Key: "m28ai"}}}}
	ok := CreateRequest{Map: "scmp_009", Seats: []Seat{{Kind: "human"}, {Kind: "ai", AI: "m28ai"}}}
	if _, err := m.validate(&ok); err != nil {
		t.Fatalf("a catalog AI refused: %v", err)
	}
	bad := CreateRequest{Map: "scmp_009", Seats: []Seat{{Kind: "human"}, {Kind: "ai", AI: "rush"}}}
	if _, err := m.validate(&bad); err == nil {
		t.Fatal("an AI the catalog doesn't list was accepted")
	}
}

// TestPoolRequestsRunAndQueue starts real (stand-in) servers: a request runs on the pool's CPU, the next waits, the
// operator's Auto stays off the pool, and each queue starts its next when a game ends.
func TestPoolRequestsRunAndQueue(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("a lobby's server is pinned to its CPUs, which needs Linux")
	}
	m := testManager(t)
	m.cfg.maxLobbies = 8
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m.cfg.serverBin = exe
	t.Setenv("SERVER_HOST_FAKE_SERVER", "1")
	// The test machine's CPUs 0 and 1, as two physical cores of one node: the fake server is pinned to them.
	m.cpus = func() []CPU {
		return []CPU{{ID: 0, Core: 0, Lobbies: []string{}}, {ID: 1, Core: 1, Lobbies: []string{}}}
	}
	m.nodes = func() []Node { return []Node{{ID: 0, CPUs: []int{0, 1}}} }
	t.Cleanup(m.stopAll)
	if _, err := m.updatePool(PoolUpdate{Enabled: boolp(true), CPUs: &[]int{1}, MaxGames: intp(2), Cores: intp(1), MaxQueue: intp(2),
		Options: &map[string]any{"Victory": "sandbox"}}); err != nil {
		t.Fatal(err)
	}
	a1, status, err := m.submitRequest(RequestBody{Player: "Ann", Map: "scmp_009", Seats: []Seat{{Kind: "human"}, {Kind: "human", Name: "Friend"}, {Kind: "ai", AI: "rush"}},
		Options: map[string]any{"UnitCap": "500"}}, "198.51.100.1")
	if err != nil || status != http.StatusOK || a1.State != "starting" || a1.Lobby == nil || a1.Position != nil {
		t.Fatalf("first request: %d %v %+v", status, err, a1)
	}
	if len(a1.Lobby.Seats) != 3 || a1.Lobby.Seats[0].Name != "Ann" || a1.Lobby.Seats[1].Join == "" {
		t.Fatalf("its lobby %+v", a1.Lobby)
	}
	l1, _ := m.get(a1.Lobby.ID)
	if l1.Side != "pool" || l1.Kind != "custom" || l1.Control != "player" || l1.Request == nil || *l1.Request != a1.ID || l1.QueuedAt != nil ||
		len(l1.CPUs) != 1 || l1.CPUs[0] != 1 || l1.StartedAt == "" {
		t.Fatalf("lobby %+v", l1)
	}
	match, _ := os.ReadFile(filepath.Join(l1.Dir, "match.lua"))
	for _, want := range []string{"MatchLobbyControl = 'player'", "Victory = 'sandbox'", "UnitCap = '500'", "AIPersonality = 'rush'"} {
		if !strings.Contains(string(match), want) {
			t.Errorf("match file lacks %q", want)
		}
	}
	// The pool's one CPU is taken: the next request waits for cores.
	b1, status, err := m.submitRequest(RequestBody{Player: "Bo", Map: "scmp_009"}, "198.51.100.2")
	if err != nil || status != http.StatusOK || b1.State != "queued" || b1.Position == nil || *b1.Position != 1 {
		t.Fatalf("second request: %d %v %+v", status, err, b1)
	}
	if q := m.listQueue(); len(q) != 1 || q[0].WaitingFor != "cores" {
		t.Fatalf("queue %+v", q)
	}
	// The operator's Auto lobby goes to CPU 0, off the pool; a second one waits in the operator queue.
	op, _, code, err := m.createOrQueue(CreateRequest{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}, Kind: "tournament", Cores: 1})
	if err != nil || op == nil || op.CPUs[0] != 0 || op.Kind != "tournament" || op.Control != "organiser" || op.Side != "operator" {
		t.Fatalf("operator lobby: %d %v %+v", code, err, op)
	}
	_, opq, code, err := m.createOrQueue(CreateRequest{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}, Kind: "tournament", Cores: 1, Queue: true})
	if err != nil || code != http.StatusAccepted || opq == nil || opq.WaitingFor != "cores" || opq.Position != 1 {
		t.Fatalf("operator queue: %d %v %+v", code, err, opq)
	}
	// The first game ends: Bo's request starts on the pool's CPU, the operator's stays queued.
	if _, err := m.stop(l1.ID); err != nil {
		t.Fatal(err)
	}
	m.pump()
	b2, err := m.getRequest(b1.ID, b1.Key)
	if err != nil || b2.State != "starting" || b2.Lobby == nil {
		t.Fatalf("after the first game: %+v %v", b2, err)
	}
	if lb, _ := m.get(b2.Lobby.ID); lb.CPUs[0] != 1 || lb.QueuedAt == nil {
		t.Fatalf("the queued request's lobby %+v", lb)
	}
	if a2, _ := m.getRequest(a1.ID, a1.Key); a2.State != "ended" || a2.Lobby == nil {
		t.Fatalf("the ended request: %+v", a2)
	}
	if q := m.listQueue(); len(q) != 1 || q[0].ID != opq.ID {
		t.Fatalf("queue after: %+v", q)
	}
	// Bo cancels before the game: the lobby stops.
	if v, status, err := m.cancelRequest(b1.ID, b1.Key); err != nil || v.State != "cancelled" {
		t.Fatalf("cancel: %d %v %+v", status, err, v)
	}
	if lb, _ := m.get(b2.Lobby.ID); running(lb.State) {
		t.Fatalf("the cancelled request's lobby runs on: %s", lb.State)
	}
	// The operator's lobby ends: its queued one starts on CPU 0.
	if _, err := m.stop(op.ID); err != nil {
		t.Fatal(err)
	}
	started := m.pump()
	if len(started) != 1 {
		t.Fatalf("started %v", started)
	}
	if lo, _ := m.get(started[0]); lo.CPUs[0] != 0 || lo.Side != "operator" || lo.QueuedAt == nil {
		t.Fatalf("the operator's queued lobby %+v", lo)
	}
	p, u := m.poolView()
	if u.Games != 0 || u.Queued != 0 || u.FreeCores != 1 || !p.Enabled {
		t.Fatalf("pool at the end %+v %+v", p, u)
	}
}
