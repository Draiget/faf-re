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

func slotManager(t *testing.T) *manager {
	m := testManager(t)
	m.cfg.maxLobbies = 3
	tm := twoNodeMachine()
	m.cpus = func() []CPU { return append([]CPU(nil), tm.cpus...) }
	m.nodes = func() []Node { return tm.nodes }
	return m
}

func TestSlotsHoldCPUsAndSpread(t *testing.T) {
	m := slotManager(t)
	made, code, err := m.createSlots(SlotRequest{Name: "Public", MaxPlayers: 4, KM: 10, Count: 2, Cores: 2, Options: map[string]any{"Victory": "sandbox"}})
	if err != nil || code != http.StatusOK || len(made) != 2 {
		t.Fatalf("%d %v %+v", code, err, made)
	}
	a, b := made[0], made[1]
	if a.Name != "Public 1" || a.State != "open" || len(a.CPUs) != 2 || len(a.Nodes) != 1 || a.ClaimCode == "" || a.ClaimCode == b.ClaimCode || !a.Reopen {
		t.Fatalf("slot %+v", a)
	}
	for _, x := range a.CPUs {
		for _, y := range b.CPUs {
			if x == y {
				t.Fatalf("slots share CPU %d: %v %v", x, a.CPUs, b.CPUs)
			}
		}
	}
	held := map[int][]string{}
	for _, c := range m.cpusWithLobbies() {
		held[c.ID] = c.Lobbies
	}
	if got := held[a.CPUs[0]]; len(got) != 1 || got[0] != a.ID {
		t.Fatalf("CPU %d holders %v", a.CPUs[0], got)
	}
	// The planner counts them as taken: a new lobby by hand on a slot's CPU is told it shares it.
	if p := place(m.machine(), PlanRequest{Players: 2, KM: 10, CPUs: []int{a.CPUs[0]}}); !strings.Contains(codes(p), "shared_cpu") {
		t.Fatalf("plan on a held CPU: %s", codes(p))
	}
	if _, code, err := m.createSlots(SlotRequest{Count: 2}); err == nil || code != http.StatusConflict {
		t.Fatalf("over the host's limit: %d %v", code, err)
	}
	if err := m.deleteSlot(a.ID); err != nil || len(m.listSlots()) != 1 {
		t.Fatalf("free: %v %d", err, len(m.listSlots()))
	}
	if err := m.deleteSlot(a.ID); err != errNoSlot {
		t.Fatalf("free twice: %v", err)
	}
	for _, bad := range []SlotRequest{{Count: 17}, {MaxPlayers: 17}, {LobbyMinutes: -1}, {Options: map[string]any{"ScenarioFile": "/x"}}, {CPUs: json.RawMessage(`"some"`)}} {
		if _, code, err := m.createSlots(bad); err == nil || code != http.StatusBadRequest {
			t.Errorf("accepted %+v: %d", bad, code)
		}
	}
}

func TestClaimRoutesWithoutAdminToken(t *testing.T) {
	m := slotManager(t)
	made, _, err := m.createSlots(SlotRequest{Name: "Open", MaxPlayers: 2})
	if err != nil {
		t.Fatal(err)
	}
	a := &api{token: "0123456789abcdef0123", m: m, maps: m.maps, procDir: t.TempDir(), hostName: "h"}
	do := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "/api/v1/slots", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("slots without the admin token: %d", w.Code)
	}
	if w := do("GET", "/api/v1/slots", a.token, ""); !strings.Contains(w.Body.String(), made[0].ClaimCode) {
		t.Fatalf("slots: %s", w.Body)
	}
	code := made[0].ClaimCode
	w := do("GET", "/api/v1/claim/"+code, "", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"max_players":2`) || strings.Contains(w.Body.String(), "cpus") {
		t.Fatalf("claim view: %d %s", w.Code, w.Body)
	}
	if w := do("GET", "/api/v1/claim/"+code+"/maps", "", ""); !strings.Contains(w.Body.String(), "scmp_009") {
		t.Fatalf("claim maps: %s", w.Body)
	}
	if w := do("GET", "/api/v1/claim/0000000000000000", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("a wrong code: %d", w.Code)
	}
	if w := do("POST", "/api/v1/claim/"+code, "", `{"player": "", "map": "scmp_009"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("no player name: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/api/v1/claim/"+code, "", `{"player": "Host", "map": "scmp_009", "seats": [{"kind":"human"},{"kind":"ai"},{"kind":"ai"}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("3 seats in a 2-player slot: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/api/v1/claim/"+code, "", `{"player": "Host", "map": "scmp_009", "seats": [{"kind":"ai"},{"kind":"human"}]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an AI as the host: %d %s", w.Code, w.Body)
	}
	if s := m.listSlots()[0]; s.State != "open" {
		t.Fatalf("a refused claim left the slot %s", s.State)
	}
	// An unknown map is the request's fault (400); 404 under /claim/<code>/ means the code is unknown.
	if w := do("GET", "/api/v1/claim/"+code+"/settings?map=nope", "", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("settings of an unknown map: %d %s", w.Code, w.Body)
	}
	// Open slots count against the host's limit for tournament lobbies too.
	m.cfg.maxLobbies = 1
	if _, status, err := m.create(CreateRequest{Map: "scmp_009", Seats: []Seat{{Kind: "human"}}}); status != http.StatusConflict || !strings.Contains(err.Error(), "open slots") {
		t.Fatalf("a lobby past the limit with a slot open: %d %v", status, err)
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

func TestClaimRunsPlayerLobbyAndReopens(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("a lobby's server is pinned to its CPUs, which needs Linux")
	}
	m := slotManager(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m.cfg.serverBin = exe
	t.Setenv("SERVER_HOST_FAKE_SERVER", "1")
	// The test machine's CPUs: the fake server is pinned to them, so they must exist here.
	m.cpus = func() []CPU { return []CPU{{ID: 0, Lobbies: []string{}}} }
	m.nodes = func() []Node { return []Node{{ID: 0, CPUs: []int{0}}} }
	made, _, err := m.createSlots(SlotRequest{Name: "Open", MaxPlayers: 4, Options: map[string]any{"Victory": "sandbox", "UnitCap": "500"}})
	if err != nil {
		t.Fatal(err)
	}
	slot := made[0]
	v, status, err := m.claim(slot.ClaimCode, ClaimRequest{Player: "Host", Map: "scmp_009",
		Seats: []Seat{{Kind: "human"}, {Kind: "human", Name: "Friend"}, {Kind: "ai", AI: "rush"}}, Options: map[string]any{"UnitCap": "1000"}})
	if err != nil {
		t.Fatalf("%d %v", status, err)
	}
	if v.Lobby == nil || len(v.Lobby.Seats) != 3 || v.Lobby.Seats[0].Name != "Host" || v.Lobby.Seats[1].Join == "" || v.Slot.State != "claimed" {
		t.Fatalf("claim %+v lobby %+v", v.Slot, v.Lobby)
	}
	if _, status, err := m.claim(slot.ClaimCode, ClaimRequest{Player: "Late", Map: "scmp_009"}); err == nil || status != http.StatusConflict {
		t.Fatalf("a second claim: %d %v", status, err)
	}
	l, _ := m.get(v.Lobby.ID)
	if l.Slot != slot.ID || l.Control != "player" || len(l.CPUs) != 1 || l.CPUs[0] != slot.CPUs[0] {
		t.Fatalf("lobby %+v", l)
	}
	for _, w := range l.Warnings {
		if w.Code == "shared_cpu" {
			t.Fatalf("the slot's own hold counted against its lobby: %+v", l.Warnings)
		}
	}
	match, _ := os.ReadFile(filepath.Join(l.Dir, "match.lua"))
	for _, want := range []string{"MatchLobbyControl = 'player'", "Victory = 'sandbox'", "UnitCap = '1000'", "AIPersonality = 'rush'"} {
		if !strings.Contains(string(match), want) {
			t.Errorf("match file lacks %q", want)
		}
	}
	held := m.cpusWithLobbies()[0].Lobbies
	if len(held) != 1 || held[0] != l.ID {
		t.Fatalf("CPU 0 holders while claimed: %v", held)
	}
	if _, err := m.stop(l.ID); err != nil {
		t.Fatal(err)
	}
	s := m.listSlots()[0]
	if s.State != "open" || s.Lobby != nil || s.ClaimCode == slot.ClaimCode || s.Games != 1 {
		t.Fatalf("after the game: %+v", s)
	}
	if _, ok := m.claimView(slot.ClaimCode); ok {
		t.Fatal("the old claim code still works")
	}
	if held := m.cpusWithLobbies()[0].Lobbies; len(held) != 1 || held[0] != s.ID {
		t.Fatalf("CPU 0 holders after the game: %v", held)
	}

	// A slot made not to reopen ends with its game, and its code then shows that rather than an unknown code.
	if err := m.deleteSlot(s.ID); err != nil {
		t.Fatal(err)
	}
	no := false
	made, _, err = m.createSlots(SlotRequest{Name: "Once", MaxPlayers: 2, Reopen: &no})
	if err != nil {
		t.Fatal(err)
	}
	once := made[0]
	v, _, err = m.claim(once.ClaimCode, ClaimRequest{Player: "Host", Map: "scmp_009"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Lobby.Warnings == nil {
		t.Fatal("the claim view has no warnings list")
	}
	if _, err := m.stop(v.Lobby.ID); err != nil {
		t.Fatal(err)
	}
	if cv, ok := m.claimView(once.ClaimCode); !ok || cv.Slot.State != "ended" {
		t.Fatalf("after the only game: %+v %v", cv, ok)
	}
	if _, status, err := m.claim(once.ClaimCode, ClaimRequest{Player: "Again", Map: "scmp_009"}); status != http.StatusConflict || !strings.Contains(err.Error(), "ended") {
		t.Fatalf("claiming an ended slot: %d %v", status, err)
	}
	if held := m.cpusWithLobbies()[0].Lobbies; len(held) != 0 {
		t.Fatalf("an ended slot still holds CPU 0: %v", held)
	}
}
