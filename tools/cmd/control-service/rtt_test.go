package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// setRTT stores a user's report as if they had just sent it: host -> ms, or -1 for a host nothing came back from.
func setRTT(t *testing.T, e *env, uid int, name string, pings map[string]float64) {
	t.Helper()
	now := time.Now().UTC()
	rec := rttRecord{UID: uid, Name: name, Updated: now.Add(-time.Minute).Format(time.RFC3339Nano), Hosts: map[string]rttEntry{}}
	for h, ms := range pings {
		if ms < 0 {
			rec.Hosts[h] = rttEntry{LossPct: 100, At: now.Format(time.RFC3339)}
		} else {
			rec.Hosts[h] = rttEntry{Ms: ms, At: now.Format(time.RFC3339)}
		}
	}
	b, _ := json.Marshal(rec)
	if err := e.store.Set(t.Context(), rttKey(uid), string(b), rttTTL); err != nil {
		t.Fatal(err)
	}
}

// pingEnv: three hosts, a (load 50), b (10) and c (30), each with its echo address.
func pingEnv(t *testing.T) (*env, map[string]*fakeHost) {
	hosts := map[string]*fakeHost{"a": newFakeHost(t, 50), "b": newFakeHost(t, 10), "c": newFakeHost(t, 30)}
	hosts["a"].echo, hosts["b"].echo, hosts["c"].echo = "203.0.113.1:27180", "203.0.113.2:27180", "203.0.113.3:27180"
	e := newEnv(t, hosts, envOpts{store: testStore(t)})
	eventually(t, "every host polled with its echo", func() bool {
		for _, p := range e.s.reg.all() {
			if s, _ := p.state(); !s.Reachable || s.RTTEcho == "" {
				return false
			}
		}
		return true
	})
	return e, hosts
}

func TestRTTHostsAndReports(t *testing.T) {
	e, _ := pingEnv(t)
	a := e.browser(uidPlayerA)
	code, out := e.do(a, http.MethodGet, "/api/v1/rtt/hosts", nil, nil)
	hosts, _ := out["hosts"].([]any)
	if code != 200 || len(hosts) != 3 || hosts[2].(map[string]any)["rtt_echo"] != "203.0.113.3:27180" || hosts[0].(map[string]any)["reachable"] != true {
		t.Fatalf("hosts to probe: %d %v", code, out)
	}
	if code, _ := e.do(nil, http.MethodGet, "/api/v1/rtt/hosts", nil, nil); code != 401 {
		t.Fatalf("without sign-in: %d", code)
	}
	// The players' host list carries the echo too.
	_, out = e.do(a, http.MethodGet, "/api/v1/hosts", nil, nil)
	if h := out["hosts"].([]any)[0].(map[string]any); h["rtt_echo"] != "203.0.113.1:27180" || h["load"] != nil {
		t.Fatalf("a player's host: %v", h)
	}
	bad := map[string]any{
		"unknown host":   map[string]any{"rtts": []any{map[string]any{"host": "zz", "ms": 10}}},
		"too slow":       map[string]any{"rtts": []any{map[string]any{"host": "a", "ms": 2500}}},
		"negative":       map[string]any{"rtts": []any{map[string]any{"host": "a", "ms": -1}}},
		"no ms":          map[string]any{"rtts": []any{map[string]any{"host": "a"}}},
		"loss over 100":  map[string]any{"rtts": []any{map[string]any{"host": "a", "ms": 10, "loss_pct": 150}}},
		"twice":          map[string]any{"rtts": []any{map[string]any{"host": "a", "ms": 10}, map[string]any{"host": "a", "ms": 12}}},
		"empty":          map[string]any{"rtts": []any{}},
		"unknown field":  map[string]any{"rtts": []any{map[string]any{"host": "a", "ms": 10}}, "uid": uidPlayerB},
		"more than kept": map[string]any{"rtts": []any{map[string]any{"host": "a", "ms": 1}, map[string]any{"host": "b", "ms": 1}, map[string]any{"host": "c", "ms": 1}, map[string]any{"host": "d", "ms": 1}}},
	}
	for name, body := range bad {
		if code, out := e.do(a, http.MethodPost, "/api/v1/rtt", body, nil); code != 400 {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if code, _ := e.do(nil, http.MethodPost, "/api/v1/rtt", map[string]any{"rtts": []any{map[string]any{"host": "a", "ms": 10}}}, e.adminHdr()); code != 403 {
		t.Fatalf("the admin token has no FAF id: %d", code)
	}
	good := map[string]any{"rtts": []any{map[string]any{"host": "a", "ms": 31.26, "loss_pct": 10}, map[string]any{"host": "b", "loss_pct": 100}}}
	code, out = e.do(a, http.MethodPost, "/api/v1/rtt", good, nil)
	if code != 200 {
		t.Fatalf("report: %d %v", code, out)
	}
	if code, _ := e.do(a, http.MethodPost, "/api/v1/rtt", good, nil); code != 429 {
		t.Fatalf("a second report at once: %d", code)
	}
	_, out = e.do(a, http.MethodGet, "/api/v1/rtt", nil, nil)
	rec := out["rtt"].(map[string]any)
	got := rec["hosts"].(map[string]any)
	if rec["uid"] != float64(uidPlayerA) || got["a"].(map[string]any)["ms"] != 31.3 || got["b"].(map[string]any)["loss_pct"] != float64(100) || got["c"] != nil {
		t.Fatalf("my report: %v", rec)
	}
	// Another player's report is theirs alone.
	_, out = e.do(e.browser(uidPlayerB), http.MethodGet, "/api/v1/rtt", nil, nil)
	if len(out["rtt"].(map[string]any)["hosts"].(map[string]any)) != 0 {
		t.Fatalf("player B sees: %v", out)
	}
	// Entries past the TTL no longer count.
	old := rttRecord{UID: uidPlayerB, Hosts: map[string]rttEntry{"a": {Ms: 5, At: time.Now().Add(-rttTTL - time.Minute).UTC().Format(time.RFC3339)}}}
	b, _ := json.Marshal(old)
	_ = e.store.Set(t.Context(), rttKey(uidPlayerB), string(b), rttTTL)
	if rec, err := e.s.rttOf(t.Context(), uidPlayerB, time.Now()); err != nil || rec != nil {
		t.Fatalf("an old report: %v %v", rec, err)
	}
}

func placementOf(t *testing.T, out map[string]any) (picked string, ranks map[string]float64, pl map[string]any) {
	t.Helper()
	pl, ok := out["placement"].(map[string]any)
	if !ok {
		t.Fatalf("no placement: %v", out)
	}
	ranks = map[string]float64{}
	for _, x := range pl["hosts"].([]any) {
		row := x.(map[string]any)
		r, _ := row["rank"].(float64)
		ranks[row["host"].(string)] = r
	}
	picked, _ = pl["picked"].(string)
	return picked, ranks, pl
}

func TestPlacementByPing(t *testing.T) {
	e, hosts := pingEnv(t)
	org := e.browser(uidOrganiser)
	body := cupLobby()
	body["placement"] = "ping"
	// Nobody measured yet: the usual order, least loaded first, and both players listed as missing.
	code, out := e.do(org, http.MethodPost, "/api/v1/placement", body, nil)
	picked, ranks, pl := placementOf(t, out)
	if code != 200 || picked != "b" || ranks["b"] != 1 || ranks["c"] != 2 || ranks["a"] != 3 || len(pl["missing"].([]any)) != 2 || pl["measured"] != float64(0) {
		t.Fatalf("no reports: %d %v", code, out)
	}
	// Worst pings: a 40 (B), b 80 (A), c 45 (B). a and c are within 10 ms: the less loaded c goes first, then a; b last
	// although it is the least loaded.
	setRTT(t, e, uidPlayerA, "A", map[string]float64{"a": 30, "b": 80, "c": 35})
	setRTT(t, e, uidPlayerB, "B", map[string]float64{"a": 40, "b": 20, "c": 45})
	code, out = e.do(org, http.MethodPost, "/api/v1/placement", body, nil)
	picked, ranks, pl = placementOf(t, out)
	if code != 200 || picked != "c" || ranks["c"] != 1 || ranks["a"] != 2 || ranks["b"] != 3 || len(pl["missing"].([]any)) != 0 {
		t.Fatalf("by ping: %d %v", code, out)
	}
	for _, x := range pl["hosts"].([]any) {
		row := x.(map[string]any)
		if row["host"] == "b" && (row["worst_ms"] != float64(80) || row["worst_player"] != "A" || row["measured"] != float64(2)) {
			t.Fatalf("b's row: %v", row)
		}
	}
	created := 0
	for _, h := range hosts {
		h.mu.Lock()
		created += len(h.created)
		h.mu.Unlock()
	}
	if created != 0 {
		t.Fatal("a preview made a lobby")
	}
	// A player nothing came back from on c: c goes after every host both reached.
	setRTT(t, e, uidPlayerB, "B", map[string]float64{"a": 40, "b": 20, "c": -1})
	_, out = e.do(org, http.MethodPost, "/api/v1/placement", body, nil)
	if picked, ranks, _ := placementOf(t, out); picked != "a" || ranks["a"] != 1 || ranks["b"] != 2 || ranks["c"] != 3 {
		t.Fatalf("c unreachable for B: %v", out)
	}
	// A host without a report from a measured player goes after those everyone measured.
	setRTT(t, e, uidPlayerB, "B", map[string]float64{"a": 40, "c": 45})
	_, out = e.do(org, http.MethodPost, "/api/v1/placement", body, nil)
	if picked, ranks, _ := placementOf(t, out); picked != "c" || ranks["b"] != 3 {
		t.Fatalf("b not measured by B: %v", out)
	}
	// A host that doesn't fit isn't a candidate, with its reason in the table.
	hosts["c"].mu.Lock()
	hosts["c"].fits = false
	hosts["c"].mu.Unlock()
	_, out = e.do(org, http.MethodPost, "/api/v1/placement", body, nil)
	picked, ranks, pl = placementOf(t, out)
	if picked != "a" || ranks["c"] != 0 {
		t.Fatalf("c doesn't fit: %v", out)
	}
	for _, x := range pl["hosts"].([]any) {
		if row := x.(map[string]any); row["host"] == "c" && (row["candidate"] != false || row["reason"] == nil) {
			t.Fatalf("c's row: %v", row)
		}
	}
	hosts["c"].mu.Lock()
	hosts["c"].fits = true
	hosts["c"].mu.Unlock()

	// Creating places it as the preview says, and answers the table.
	setRTT(t, e, uidPlayerB, "B", map[string]float64{"a": 40, "b": 20, "c": 45})
	code, out = e.do(org, http.MethodPost, "/api/v1/lobbies", body, nil)
	if code != 200 || out["lobby"].(map[string]any)["host"] != "c" {
		t.Fatalf("create by ping: %d %v", code, out)
	}
	if picked, _, _ := placementOf(t, out); picked != "c" {
		t.Fatalf("create's placement: %v", out)
	}
	// Load placement answers as before, without a table.
	delete(body, "placement")
	code, out = e.do(org, http.MethodPost, "/api/v1/lobbies", body, nil)
	if code != 200 || out["lobby"].(map[string]any)["host"] != "b" || out["placement"] != nil {
		t.Fatalf("create by load: %d %v", code, out)
	}
	// An open seat is missing; a named host and an unknown mode are refused; players can't preview.
	loose := map[string]any{"map": "scmp_009", "placement": "ping", "seats": []any{map[string]any{"kind": "human", "uid": uidPlayerA, "name": "A"}, map[string]any{"kind": "human"}}}
	_, out = e.do(org, http.MethodPost, "/api/v1/placement", loose, nil)
	if _, _, pl := placementOf(t, out); len(pl["missing"].([]any)) != 1 || pl["missing"].([]any)[0].(map[string]any)["why"] != "open seat" {
		t.Fatalf("open seat: %v", out)
	}
	body["placement"], body["host"] = "ping", "a"
	if code, _ := e.do(org, http.MethodPost, "/api/v1/lobbies", body, nil); code != 400 {
		t.Fatalf("ping with a named host: %d", code)
	}
	delete(body, "host")
	body["placement"] = "fastest"
	if code, _ := e.do(org, http.MethodPost, "/api/v1/lobbies", body, nil); code != 400 {
		t.Fatalf("unknown placement: %d", code)
	}
	body["placement"] = "ping"
	if code, _ := e.do(e.browser(uidPlayerA), http.MethodPost, "/api/v1/placement", body, nil); code != 403 {
		t.Fatalf("a player's preview: %d", code)
	}
}

func TestRequestByPing(t *testing.T) {
	e, hosts := pingEnv(t)
	for _, h := range hosts {
		h.mu.Lock()
		h.poolEnabled = true
		h.mu.Unlock()
	}
	eventually(t, "pools seen", func() bool {
		for _, p := range e.s.reg.all() {
			if s, _ := p.state(); !s.PlayerHosting {
				return false
			}
		}
		return true
	})
	a := e.browser(uidPlayerA)
	// The usual order would pick b (no queue, least loaded); A's ping to b is far worse.
	setRTT(t, e, uidPlayerA, "PlayerA", map[string]float64{"a": 30, "b": 90, "c": 60})
	// Another seat's FAF id is the requester's word: that user's report isn't read (it would rule out a).
	setRTT(t, e, uidPlayerB, "PlayerB", map[string]float64{"a": 500, "b": 1, "c": 1})
	body := map[string]any{"map": "scmp_007", "placement": "ping", "seats": []any{map[string]any{"kind": "human"},
		map[string]any{"kind": "human", "name": "Bo", "uid": uidPlayerB}}}
	code, out := e.do(a, http.MethodPost, "/api/v1/requests", body, nil)
	if code != 200 || out["request"].(map[string]any)["host"] != "a" {
		t.Fatalf("request by ping: %d %v", code, out)
	}
	if picked, ranks, pl := placementOf(t, out); picked != "a" || ranks["c"] != 2 || ranks["b"] != 3 || pl["players"] != float64(1) {
		t.Fatalf("request's placement: %v", out)
	}
	delete(body, "placement")
	if code, out := e.do(a, http.MethodPost, "/api/v1/requests", body, nil); code != 200 || out["request"].(map[string]any)["host"] != "b" {
		t.Fatalf("request by the usual order: %d %v", code, out)
	}
}
