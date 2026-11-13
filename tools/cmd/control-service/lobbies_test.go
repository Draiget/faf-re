package main

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestRolesAndOrganising(t *testing.T) {
	cfg := &Config{Tournaments: []Tournament{{ID: "cup", Organisers: []int{uidTO}, Players: []int{uidPlayerA}}}}
	cfg.Roles.Admins, cfg.Roles.Organisers = []int{uidAdmin}, []int{uidOrganiser}
	cases := []struct {
		uid        int
		roles      string
		cup, loose bool
	}{
		{uidAdmin, "admin organiser player", true, true},
		{uidOrganiser, "organiser player", true, true},
		{uidTO, "organiser player", true, false},
		{uidPlayerA, "player", false, false},
		{uidOutsider, "player", false, false},
	}
	for _, c := range cases {
		p := cfg.principal(c.uid, "x", "session")
		if got := strings.Join(cfg.roles(p), " "); got != c.roles {
			t.Errorf("%d: roles %q, want %q", c.uid, got, c.roles)
		}
		if cfg.canOrganise(p, "cup") != c.cup || cfg.canOrganise(p, "") != c.loose {
			t.Errorf("%d: organise cup %v, outside tournaments %v", c.uid, cfg.canOrganise(p, "cup"), cfg.canOrganise(p, ""))
		}
		if cfg.canOrganise(p, "nope") != (c.uid == uidAdmin || c.uid == uidOrganiser) {
			t.Errorf("%d: an unknown tournament", c.uid)
		}
	}
}

func TestAllowlist(t *testing.T) {
	cfg := &Config{Tournaments: []Tournament{{ID: "cup", Name: "Cup", Organisers: []int{uidTO}, Players: []int{uidPlayerA, uidPlayerB}, Observers: []int{uidCaster}}}}
	ok := createBody{Tournament: "cup", Seats: []seatIn{{Kind: "human", UID: uidPlayerA}, {Kind: "human", UID: uidPlayerB}, {Kind: "ai", AI: "rush"}},
		Observers: []observerIn{{UID: uidCaster, Name: "Caster"}, {UID: uidTO, Name: "TO", Referee: true}}}
	if err := checkAllowlist(cfg, &ok); err != nil {
		t.Fatalf("the listed players and observers: %v", err)
	}
	bad := map[string]createBody{
		"unlisted player":   {Tournament: "cup", Seats: []seatIn{{Kind: "human", UID: uidOutsider}}},
		"open seat":         {Tournament: "cup", Seats: []seatIn{{Kind: "human"}}},
		"player twice":      {Tournament: "cup", Seats: []seatIn{{Kind: "human", UID: uidPlayerA}, {Kind: "human", UID: uidPlayerA}}},
		"unlisted observer": {Tournament: "cup", Seats: []seatIn{{Kind: "human", UID: uidPlayerA}}, Observers: []observerIn{{UID: uidOutsider, Name: "x"}}},
		"player observing":  {Tournament: "cup", Seats: []seatIn{{Kind: "human", UID: uidPlayerA}}, Observers: []observerIn{{UID: uidPlayerA, Name: "x"}}},
		"nameless observer": {Seats: []seatIn{{Kind: "human"}}, Observers: []observerIn{{}}},
		"AI with an id":     {Seats: []seatIn{{Kind: "ai", UID: 5}}},
		"no tournament":     {Tournament: "nope", Seats: []seatIn{{Kind: "human"}}},
	}
	for name, b := range bad {
		if err := checkAllowlist(cfg, &b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	loose := createBody{Seats: []seatIn{{Kind: "human"}, {Kind: "human", UID: uidOutsider}}}
	if err := checkAllowlist(cfg, &loose); err != nil {
		t.Errorf("a lobby outside tournaments has no list: %v", err)
	}
}

func lobbyKeys(t *testing.T, e *env) []string {
	t.Helper()
	ls, err := e.s.cachedLobbies(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for _, l := range ls {
		keys = append(keys, l.Key)
	}
	return keys
}

func cupLobby() map[string]any {
	return map[string]any{"tournament": "cup", "map": "scmp_009", "start_when_ready": 10,
		"seats": []any{map[string]any{"kind": "human", "name": "A", "uid": uidPlayerA, "team": 2},
			map[string]any{"kind": "human", "name": "B", "uid": uidPlayerB, "team": 3}},
		"observers": []any{map[string]any{"uid": uidCaster, "name": "Caster"}}}
}

func TestHostsArePolledAndCached(t *testing.T) {
	a, b := newFakeHost(t, 50), newFakeHost(t, 10)
	a.addLobby(map[string]any{"id": "l7", "name": "from the dashboard", "state": "lobby", "seats": []any{}, "observers": []any{}})
	a.setStatus("l7", map[string]any{"phase": "lobby", "seats": []any{map[string]any{"uid": 1001, "name": "X", "ready": "yes",
		"ping_ms": 40, "mods": "secret mod list", "joined": true}}})
	e := newEnv(t, map[string]*fakeHost{"a": a, "b": b}, envOpts{store: testStore(t)})
	eventually(t, "lobby a/l7 cached", func() bool { return slices.Contains(lobbyKeys(t, e), "a/l7") })
	eventually(t, "both hosts in the store", func() bool {
		ka, _ := e.store.Keys(t.Context(), "host:")
		return len(ka) == 2
	})
	_, out := e.do(nil, http.MethodGet, "/api/v1/hosts", nil, e.adminHdr())
	hosts := out["hosts"].([]any)
	if len(hosts) != 2 || hosts[0].(map[string]any)["load"] != float64(50) || hosts[0].(map[string]any)["cpu_model"] != "Fake CPU" {
		t.Fatalf("hosts for an admin: %v", hosts)
	}
	_, out = e.do(e.browser(uidPlayerA), http.MethodGet, "/api/v1/hosts", nil, nil)
	if h := out["hosts"].([]any)[0].(map[string]any); h["cpu_model"] != nil || h["reachable"] != true {
		t.Fatalf("hosts for a player: %v", h)
	}
	// A player sees the status without its mods; the admin all of it.
	_, out = e.do(e.browser(uidPlayerA), http.MethodGet, "/api/v1/lobbies/a/l7", nil, nil)
	l := out["lobby"].(map[string]any)
	seat := l["status"].(map[string]any)["seats"].([]any)[0].(map[string]any)
	if seat["mods"] != nil || seat["ready"] != "yes" || l["origin"] != "host" || l["can_operate"] != false || l["host_record"] != nil {
		t.Fatalf("player's view: %v", l)
	}
	_, out = e.do(nil, http.MethodGet, "/api/v1/lobbies/a/l7", nil, e.adminHdr())
	if out["lobby"].(map[string]any)["status"].(map[string]any)["seats"].([]any)[0].(map[string]any)["mods"] != "secret mod list" {
		t.Fatalf("admin's view: %v", out)
	}
	// Organisers can't run a lobby made outside the service; admins can.
	if code, _ := e.do(e.browser(uidOrganiser), http.MethodPost, "/api/v1/lobbies/a/l7/ops/pause", map[string]any{}, nil); code != 403 {
		t.Fatalf("organiser on a dashboard lobby: %d", code)
	}
	if code, _ := e.do(nil, http.MethodPost, "/api/v1/lobbies/a/l7/ops/pause", map[string]any{}, e.adminHdr()); code != 200 {
		t.Fatalf("admin on a dashboard lobby: %d", code)
	}
	// The lobby leaves the host's list: it leaves the cache.
	a.mu.Lock()
	a.lobbies = nil
	a.mu.Unlock()
	eventually(t, "a/l7 gone", func() bool { return !slices.Contains(lobbyKeys(t, e), "a/l7") })
}

func TestCreateOnLeastLoadedHostThatFits(t *testing.T) {
	a, b := newFakeHost(t, 50), newFakeHost(t, 10)
	e := newEnv(t, map[string]*fakeHost{"a": a, "b": b}, envOpts{store: testStore(t)})
	eventually(t, "hosts polled", func() bool {
		ha, _ := e.s.reg.get("a").state()
		hb, _ := e.s.reg.get("b").state()
		return ha.Reachable && hb.Reachable
	})
	to := e.browser(uidTO)
	code, out := e.do(to, http.MethodPost, "/api/v1/lobbies", cupLobby(), nil)
	if code != 200 || out["lobby"].(map[string]any)["host"] != "b" {
		t.Fatalf("create: %d %v", code, out)
	}
	b.mu.Lock()
	sent := b.created[0]
	b.mu.Unlock()
	if sent["control"] != "organiser" || sent["kind"] != "tournament" || sent["name"] != "The Cup" {
		t.Fatalf("what the host got: %v", sent)
	}
	if o := sent["observers"].([]any)[0].(map[string]any); o["uid"] != nil || o["name"] != "Caster" {
		t.Fatalf("observers go to the host without FAF ids: %v", o)
	}
	// b no longer fits: the next lobby goes to a.
	b.mu.Lock()
	b.fits = false
	b.mu.Unlock()
	code, out = e.do(to, http.MethodPost, "/api/v1/lobbies", cupLobby(), nil)
	if code != 200 || out["lobby"].(map[string]any)["host"] != "a" {
		t.Fatalf("second create: %d %v", code, out)
	}
	// Neither fits: 409 with each host's reason.
	a.mu.Lock()
	a.fits = false
	a.mu.Unlock()
	code, out = e.do(to, http.MethodPost, "/api/v1/lobbies", cupLobby(), nil)
	if code != 409 || !strings.Contains(out["error"].(string), "no free cores") {
		t.Fatalf("nothing fits: %d %v", code, out)
	}
	// A map no host has.
	l := cupLobby()
	l["map"] = "nowhere"
	code, out = e.do(to, http.MethodPost, "/api/v1/lobbies", l, nil)
	if code != 409 || !strings.Contains(out["error"].(string), `no map "nowhere"`) {
		t.Fatalf("unknown map: %d %v", code, out)
	}
	// A named host gets the request as it is (its own answer stands).
	l = cupLobby()
	l["host"] = "a"
	if code, _ = e.do(to, http.MethodPost, "/api/v1/lobbies", l, nil); code != 409 {
		t.Fatalf("named host that doesn't fit: %d", code)
	}
	l["host"] = "zz"
	if code, _ = e.do(to, http.MethodPost, "/api/v1/lobbies", l, nil); code != 404 {
		t.Fatalf("unknown host: %d", code)
	}
}

func TestCreateFollowsRolesAndAllowlist(t *testing.T) {
	h := newFakeHost(t, 10)
	e := newEnv(t, map[string]*fakeHost{"h": h}, envOpts{store: testStore(t)})
	eventually(t, "host polled", func() bool { s, _ := e.s.reg.get("h").state(); return s.Reachable })
	player, to := e.browser(uidPlayerA), e.browser(uidTO)
	if code, _ := e.do(player, http.MethodPost, "/api/v1/lobbies", cupLobby(), nil); code != 403 {
		t.Fatalf("a player making a cup lobby: %d", code)
	}
	loose := cupLobby()
	delete(loose, "tournament")
	if code, _ := e.do(to, http.MethodPost, "/api/v1/lobbies", loose, nil); code != 403 {
		t.Fatalf("the cup's organiser outside the cup: %d", code)
	}
	if code, _ := e.do(e.browser(uidOrganiser), http.MethodPost, "/api/v1/lobbies", loose, nil); code != 200 {
		t.Fatalf("a global organiser outside tournaments: %d", code)
	}
	l := cupLobby()
	l["seats"] = append(l["seats"].([]any), map[string]any{"kind": "human", "uid": uidOutsider})
	code, out := e.do(to, http.MethodPost, "/api/v1/lobbies", l, nil)
	if code != 400 || !strings.Contains(out["error"].(string), "player list") {
		t.Fatalf("an unlisted player: %d %v", code, out)
	}
	l = cupLobby()
	l["force"] = true
	if code, _ := e.do(to, http.MethodPost, "/api/v1/lobbies", l, nil); code != 403 {
		t.Fatalf("force by an organiser: %d", code)
	}
	l = cupLobby()
	l["queue"] = true
	if code, _ := e.do(to, http.MethodPost, "/api/v1/lobbies", l, nil); code != 400 {
		t.Fatalf("an unknown field: %d", code)
	}
}

func TestLobbyViewsOpsAndStop(t *testing.T) {
	h := newFakeHost(t, 10)
	e := newEnv(t, map[string]*fakeHost{"h": h}, envOpts{store: testStore(t)})
	eventually(t, "host polled", func() bool { s, _ := e.s.reg.get("h").state(); return s.Reachable })
	to := e.browser(uidTO)
	code, out := e.do(to, http.MethodPost, "/api/v1/lobbies", cupLobby(), nil)
	if code != 200 {
		t.Fatalf("create: %d %v", code, out)
	}
	key := out["lobby"].(map[string]any)["key"].(string)
	eventually(t, "lobby cached", func() bool { return slices.Contains(lobbyKeys(t, e), key) })
	path := "/api/v1/lobbies/" + key
	view := func(uid int) map[string]any {
		_, out := e.do(e.browser(uid), http.MethodGet, path, nil, nil)
		return out["lobby"].(map[string]any)
	}
	joins := func(l map[string]any) int {
		n := 0
		for _, s := range l["seats"].([]any) {
			if s.(map[string]any)["join"] != nil {
				n++
			}
		}
		return n
	}
	a := view(uidPlayerA)
	if joins(a) != 0 || a["you"].(map[string]any)["join"] != "/connectserver 203.0.113.5:27200 /servertoken secret1 /serveruid 10" || a["host_record"] != nil {
		t.Fatalf("player A sees: %v", a)
	}
	if b := view(uidPlayerB); !strings.Contains(b["you"].(map[string]any)["join"].(string), "secret2") {
		t.Fatalf("player B sees: %v", b)
	}
	c := view(uidCaster)
	if c["you"].(map[string]any)["watch"] != "/replay gpgnet://203.0.113.5:27201/watch1" || c["observers"].([]any)[0].(map[string]any)["uid"] != float64(uidCaster) {
		t.Fatalf("the caster sees: %v", c)
	}
	if o := view(uidOutsider); o["you"] != nil || joins(o) != 0 || strings.Contains(mustJSON(o), "secret") || strings.Contains(mustJSON(o), "watch1") {
		t.Fatalf("an outsider sees: %v", o)
	}
	if t2 := view(uidTO); joins(t2) != 2 || t2["host_record"] == nil || t2["can_operate"] != true || t2["origin"] != "organised" || t2["tournament"] != "cup" {
		t.Fatalf("the organiser sees: %v", t2)
	}
	// Ops: the cup's organisers and admins; not players; only the known ops.
	if code, _ := e.do(e.browser(uidPlayerA), http.MethodPost, path+"/ops/force_start", nil, nil); code != 403 {
		t.Fatalf("player op: %d", code)
	}
	if code, _ := e.do(to, http.MethodPost, path+"/ops/eject", map[string]any{"uid": uidPlayerB, "reason": "test"}, nil); code != 200 {
		t.Fatalf("organiser op: %d", code)
	}
	if code, _ := e.do(to, http.MethodPost, path+"/ops/rm_rf", nil, nil); code != 400 {
		t.Fatalf("unknown op: %d", code)
	}
	h.mu.Lock()
	ops := slices.Clone(h.ops)
	h.mu.Unlock()
	if len(ops) != 1 || !strings.HasPrefix(ops[0], `eject {"reason":"test","uid":11}`) {
		t.Fatalf("ops the host got: %q", ops)
	}
	if code, _ := e.do(e.browser(uidPlayerA), http.MethodGet, path+"/armies", nil, nil); code != 403 {
		t.Fatalf("player armies: %d", code)
	}
	if code, _ := e.do(to, http.MethodGet, path+"/armies", nil, nil); code != 200 {
		t.Fatalf("organiser armies: %d", code)
	}
	if code, _ := e.do(e.browser(uidPlayerA), http.MethodDelete, path, nil, nil); code != 403 {
		t.Fatalf("player stop: %d", code)
	}
	if code, _ := e.do(to, http.MethodDelete, path, nil, nil); code != 200 {
		t.Fatalf("organiser stop: %d", code)
	}
	eventually(t, "stopped in the cache", func() bool {
		st, _ := e.s.cachedLobby(t.Context(), key)
		return st != nil && st.parsed().State == "stopped"
	})
}

func TestUnreachableHostKeepsLobbiesStale(t *testing.T) {
	h := newFakeHost(t, 10)
	h.addLobby(map[string]any{"id": "l1", "state": "lobby", "seats": []any{}, "observers": []any{}})
	e := newEnv(t, map[string]*fakeHost{"h": h}, envOpts{store: testStore(t)})
	eventually(t, "lobby cached", func() bool { return slices.Contains(lobbyKeys(t, e), "h/l1") })
	h.srv.CloseClientConnections()
	h.srv.Close()
	eventually(t, "stale", func() bool {
		st, _ := e.s.cachedLobby(t.Context(), "h/l1")
		hs, _ := e.s.reg.get("h").state()
		return st != nil && st.Stale && !hs.Reachable && hs.Error != ""
	})
}

func TestPlayerRequests(t *testing.T) {
	h := newFakeHost(t, 10)
	e := newEnv(t, map[string]*fakeHost{"h": h}, envOpts{store: testStore(t)})
	eventually(t, "host polled", func() bool { s, _ := e.s.reg.get("h").state(); return s.Reachable })
	a := e.browser(uidPlayerA)
	body := map[string]any{"map": "scmp_007", "seats": []any{map[string]any{"kind": "human"}, map[string]any{"kind": "ai", "ai": "rush"}}}
	if code, _ := e.do(a, http.MethodPost, "/api/v1/requests", body, nil); code != 409 {
		t.Fatalf("player hosting off on every host: %d", code)
	}
	h.mu.Lock()
	h.poolEnabled, h.poolAccess = true, "code"
	h.mu.Unlock()
	eventually(t, "pool seen", func() bool { s, _ := e.s.reg.get("h").state(); return s.PlayerHosting })
	code, out := e.do(a, http.MethodPost, "/api/v1/requests", body, nil)
	if code != 200 {
		t.Fatalf("request: %d %v", code, out)
	}
	req := out["request"].(map[string]any)
	if req["key"] != nil || req["ref"] == nil || req["code"] != nil {
		t.Fatalf("the answer must hide the key and code: %v", req)
	}
	h.mu.Lock()
	sent := h.requests[0]
	h.mu.Unlock()
	seat1 := sent["seats"].([]any)[0].(map[string]any)
	if sent["player"] != "PlayerA" || sent["code"] != "c0de" || seat1["uid"] != float64(uidPlayerA) {
		t.Fatalf("what the host got: %v", sent)
	}
	ref := req["ref"].(string)
	_, out = e.do(a, http.MethodGet, "/api/v1/requests", nil, nil)
	if l := out["requests"].([]any); len(l) != 1 || l[0].(map[string]any)["state"] != "queued" {
		t.Fatalf("my requests: %v", out)
	}
	if code, _ := e.do(e.browser(uidPlayerB), http.MethodGet, "/api/v1/requests/"+ref, nil, nil); code != 404 {
		t.Fatalf("another player's request: %d", code)
	}
	code, out = e.do(a, http.MethodDelete, "/api/v1/requests/"+ref, nil, nil)
	if code != 200 || out["request"].(map[string]any)["state"] != "cancelled" {
		t.Fatalf("cancel: %d %v", code, out)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
