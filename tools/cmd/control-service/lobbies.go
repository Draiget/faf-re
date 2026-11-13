package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

// cachedLobbies reads every lobby's state from the store (what the pollers wrote), so that any instance serving the
// web reads the same.
func (s *server) cachedLobbies(ctx context.Context) ([]*LobbyState, error) {
	keys, err := s.store.Keys(ctx, "lobby:")
	if err != nil {
		return nil, err
	}
	out := []*LobbyState{}
	for _, k := range keys {
		v, ok, err := s.store.Get(ctx, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		var st LobbyState
		if json.Unmarshal([]byte(v), &st) == nil {
			out = append(out, &st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (s *server) cachedLobby(ctx context.Context, key string) (*LobbyState, error) {
	v, ok, err := s.store.Get(ctx, "lobby:"+key)
	if err != nil || !ok {
		return nil, err
	}
	var st LobbyState
	if err := json.Unmarshal([]byte(v), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// GET /api/v1/lobbies[?host=<name>&tournament=<id>&running=1]
func (s *server) listLobbies(w http.ResponseWriter, r *http.Request, cfg *Config, who Principal) {
	all, err := s.cachedLobbies(r.Context())
	if err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	q := r.URL.Query()
	out := []lobbyView{}
	for _, st := range all {
		v := viewLobby(cfg, who, st)
		if (q.Get("host") != "" && v.Host != q.Get("host")) || (q.Get("tournament") != "" && v.Tournament != q.Get("tournament")) ||
			(q.Get("running") == "1" && !runningState(v.State)) {
			continue
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lobbies": out})
}

type seatIn struct {
	Seat    int    `json:"seat,omitempty"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	UID     int    `json:"uid,omitempty"`
	AI      string `json:"ai,omitempty"`
	Faction int    `json:"faction,omitempty"`
	Team    int    `json:"team,omitempty"`
}

type observerIn struct {
	UID     int    `json:"uid"`
	Name    string `json:"name"`
	Referee bool   `json:"referee"`
}

// createBody is POST /api/v1/lobbies: an organised lobby. The lobby fields are the host's (docs/SERVER_DASHBOARD.md);
// host, region and tournament are the service's.
type createBody struct {
	Host           string          `json:"host"`      // a host by name; empty: the least loaded host that fits
	Region         string          `json:"region"`    // only hosts of this region when picking
	Placement      string          `json:"placement"` // "load" (default) or "ping": the lowest worst player ping (rtt.go)
	Tournament     string          `json:"tournament"`
	Name           string          `json:"name"`
	Map            string          `json:"map"`
	Seats          []seatIn        `json:"seats"`
	Observers      []observerIn    `json:"observers"`
	Options        map[string]any  `json:"options"`
	ObserverDelay  float64         `json:"observer_delay_seconds"`
	StartWhenReady float64         `json:"start_when_ready"`
	LobbyMinutes   float64         `json:"lobby_minutes"`
	CPUs           json.RawMessage `json:"cpus"`
	Cores          int             `json:"cores"`
	Force          bool            `json:"force"`
}

// checkAllowlist applies the tournament's lists: every human seat is a listed player with a FAF id, every observer a
// listed observer or organiser, nobody twice.
func checkAllowlist(cfg *Config, b *createBody) error {
	uids := map[int]bool{}
	var t *Tournament
	if b.Tournament != "" {
		if t = cfg.tournament(b.Tournament); t == nil {
			return fmt.Errorf("no tournament %q", b.Tournament)
		}
	}
	for i, seat := range b.Seats {
		if seat.Kind != "human" {
			if seat.UID != 0 {
				return fmt.Errorf("seat %d: only a human seat has a FAF id", i+1)
			}
			continue
		}
		if seat.UID < 0 {
			return fmt.Errorf("seat %d: FAF ids are positive", i+1)
		}
		if seat.UID != 0 {
			if uids[seat.UID] {
				return fmt.Errorf("FAF user %d is given two places", seat.UID)
			}
			uids[seat.UID] = true
		}
		if t == nil {
			continue
		}
		if seat.UID == 0 {
			return fmt.Errorf("seat %d: a tournament's seats are for its listed players: give the FAF id", i+1)
		}
		if !slices.Contains(t.Players, seat.UID) {
			return fmt.Errorf("seat %d: FAF user %d isn't on %s's player list", i+1, seat.UID, t.Name)
		}
	}
	for i, o := range b.Observers {
		if strings.TrimSpace(o.Name) == "" {
			return fmt.Errorf("observer %d needs a name", i+1)
		}
		if o.UID < 0 {
			return fmt.Errorf("observer %d: FAF ids are positive", i+1)
		}
		if o.UID != 0 {
			if uids[o.UID] {
				return fmt.Errorf("FAF user %d is given two places", o.UID)
			}
			uids[o.UID] = true
		}
		if t == nil {
			continue
		}
		if o.UID == 0 {
			return fmt.Errorf("observer %d: a tournament's observers are listed users: give the FAF id", i+1)
		}
		if !slices.Contains(t.Observers, o.UID) && !slices.Contains(t.Organisers, o.UID) {
			return fmt.Errorf("observer %d: FAF user %d isn't on %s's observer or organiser list", i+1, o.UID, t.Name)
		}
	}
	return nil
}

// candidate is a host a lobby could go to, with why it ranks where it does.
type candidate struct {
	p      *poller
	fits   bool
	load   float64
	reason string
	row    int // its row in the placement table
}

// pickHosts ranks the hosts for a new lobby: reachable, with the map, in the region; then those whose planner says
// it fits, least loaded first, or by the players' worst ping with "placement": "ping" (then the placement table is
// the answer's too). A named host is the only candidate.
func (s *server) pickHosts(ctx context.Context, b *createBody) ([]candidate, []string, *placement, error) {
	var pollers []*poller
	if b.Host != "" {
		if p := s.reg.get(b.Host); p != nil {
			pollers = []*poller{p}
		}
		return []candidate{{p: firstOr(pollers), fits: true}}, nil, nil, nil
	}
	reasons := []string{}
	cands := []candidate{}
	rows := []hostPlacement{}
	skip := func(row hostPlacement, why string) {
		row.Reason = why
		rows = append(rows, row)
		reasons = append(reasons, row.Host+": "+why)
	}
	for _, p := range s.reg.all() {
		h, _ := p.state()
		name := p.h.cfg.Name
		if b.Region != "" && h.Region != b.Region {
			continue
		}
		row := hostPlacement{Host: name, Region: h.Region, Load: h.Load}
		if !h.Reachable {
			skip(row, "not reachable")
			continue
		}
		maps, err := p.mapList(ctx)
		if err != nil {
			skip(row, strings.TrimPrefix(err.Error(), "host "+name+": "))
			continue
		}
		km := 0
		for _, m := range maps {
			if strings.EqualFold(m.ID, b.Map) {
				km = m.KM
			}
		}
		if km == 0 {
			skip(row, fmt.Sprintf("no map %q", b.Map))
			continue
		}
		plan := map[string]any{"players": max(len(b.Seats), 1), "km": km, "side": "operator"}
		if b.Cores > 0 {
			plan["cores"] = b.Cores
		}
		body, _ := json.Marshal(plan)
		code, resp, err := p.h.call(ctx, http.MethodPost, "/api/v1/plan", body)
		var doc struct {
			Plan struct {
				Fits     bool `json:"fits"`
				Warnings []struct {
					Severity string `json:"severity"`
					Text     string `json:"text"`
				} `json:"warnings"`
			} `json:"plan"`
		}
		if err != nil || code != http.StatusOK || json.Unmarshal(resp, &doc) != nil {
			skip(row, fmt.Sprintf("its planner didn't answer (%d %v)", code, err))
			continue
		}
		c := candidate{p: p, fits: doc.Plan.Fits, load: h.Load}
		if !c.fits {
			why := []string{}
			for _, w := range doc.Plan.Warnings {
				if w.Severity == "error" {
					why = append(why, w.Text)
				}
			}
			c.reason = name + ": doesn't fit now: " + strings.Join(why, "; ")
			skip(row, "doesn't fit now: "+strings.Join(why, "; "))
			continue
		}
		row.Candidate = true
		c.row = len(rows)
		rows = append(rows, row)
		cands = append(cands, c)
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].load < cands[j].load })
	if b.Placement != "ping" {
		return cands, reasons, nil, nil
	}
	order, pl, err := s.rankByPing(ctx, b.Seats, rows, func(i, j int) bool { return rows[i].Load < rows[j].Load })
	if err != nil {
		return nil, nil, nil, err
	}
	byRow := map[int]candidate{}
	for _, c := range cands {
		byRow[c.row] = c
	}
	ranked := make([]candidate, 0, len(order))
	for _, i := range order {
		ranked = append(ranked, byRow[i])
	}
	return ranked, reasons, pl, nil
}

func firstOr(ps []*poller) *poller {
	if len(ps) == 0 {
		return nil
	}
	return ps[0]
}

// decodeCreate reads and checks a new organised lobby's body (also a placement preview's): the roles, the lists, the
// host and the placement mode. It has answered when ok is false.
func (s *server) decodeCreate(w http.ResponseWriter, r *http.Request, cfg *Config, who Principal) (*createBody, bool) {
	var b createBody
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		fail(w, http.StatusBadRequest, fmt.Errorf("body: %w", err))
		return nil, false
	}
	if !cfg.canOrganise(who, b.Tournament) {
		fail(w, http.StatusForbidden, fmt.Errorf("%w: organised lobbies of %s are for its organisers and admins", errForbidden,
			orNone(b.Tournament)))
		return nil, false
	}
	if b.Force && !who.Admin {
		fail(w, http.StatusForbidden, errors.New("only an admin may force a lobby past the planner's errors"))
		return nil, false
	}
	if strings.TrimSpace(b.Map) == "" || len(b.Seats) == 0 {
		fail(w, http.StatusBadRequest, errors.New("a lobby needs a map and seats"))
		return nil, false
	}
	if err := checkAllowlist(cfg, &b); err != nil {
		fail(w, http.StatusBadRequest, err)
		return nil, false
	}
	if b.Host != "" && cfg.host(b.Host) == nil {
		fail(w, http.StatusNotFound, fmt.Errorf("no host %q", b.Host))
		return nil, false
	}
	switch b.Placement {
	case "", "load":
	case "ping":
		if b.Host != "" {
			fail(w, http.StatusBadRequest, errors.New(`"placement": "ping" picks the host: leave host empty`))
			return nil, false
		}
	default:
		fail(w, http.StatusBadRequest, fmt.Errorf(`placement is "load" or "ping", not %q`, b.Placement))
		return nil, false
	}
	return &b, true
}

// POST /api/v1/lobbies: an organised lobby (control organiser, kind tournament) on a chosen host, the least loaded
// one that fits, or the one with the lowest worst player ping.
func (s *server) createLobby(w http.ResponseWriter, r *http.Request, cfg *Config, who Principal) {
	pb, ok := s.decodeCreate(w, r, cfg, who)
	if !ok {
		return
	}
	b := *pb
	observers := []map[string]any{}
	for _, o := range b.Observers {
		observers = append(observers, map[string]any{"name": o.Name, "referee": o.Referee})
	}
	forward := map[string]any{"name": b.Name, "map": b.Map, "seats": b.Seats, "observers": observers, "options": b.Options,
		"observer_delay_seconds": b.ObserverDelay, "start_when_ready": b.StartWhenReady, "lobby_minutes": b.LobbyMinutes,
		"cores": b.Cores, "force": b.Force, "control": "organiser", "kind": "tournament"}
	if len(b.CPUs) > 0 {
		if b.Host == "" && strings.TrimSpace(string(b.CPUs)) != `"auto"` {
			fail(w, http.StatusBadRequest, errors.New("CPUs picked by id need a host"))
			return
		}
		forward["cpus"] = b.CPUs
	}
	if forward["name"] == "" && b.Tournament != "" {
		forward["name"] = cfg.tournament(b.Tournament).Name
	}
	body, _ := json.Marshal(forward)
	cands, reasons, pl, err := s.pickHosts(r.Context(), &b)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	// With "placement": "ping" every answer carries the placement table, a refusal too.
	refuse := func(code int, err error) {
		if pl == nil {
			fail(w, code, err)
			return
		}
		writeJSON(w, code, map[string]any{"ok": false, "error": err.Error(), "placement": pl})
	}
	if len(cands) == 0 || cands[0].p == nil {
		refuse(http.StatusConflict, fmt.Errorf("no host can take this lobby now: %s", orNone(strings.Join(reasons, "; "))))
		return
	}
	for i, c := range cands {
		code, resp, err := c.p.h.call(r.Context(), http.MethodPost, "/api/v1/lobbies", body)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		if code == http.StatusConflict && i+1 < len(cands) {
			reasons = append(reasons, c.p.h.cfg.Name+": "+hostError(resp))
			continue // taken meanwhile: the next host
		}
		if code != http.StatusOK {
			if code == http.StatusAccepted {
				code = http.StatusBadGateway // the service never asks to queue; a host shouldn't have queued it
			}
			refuse(code, fmt.Errorf("host %s: %s", c.p.h.cfg.Name, hostError(resp)))
			return
		}
		var doc struct {
			Lobby json.RawMessage `json:"lobby"`
		}
		var l hostLobby
		if json.Unmarshal(resp, &doc) != nil || json.Unmarshal(doc.Lobby, &l) != nil || l.ID == "" {
			fail(w, http.StatusBadGateway, fmt.Errorf("host %s answered without a lobby", c.p.h.cfg.Name))
			return
		}
		key := c.p.h.cfg.Name + "/" + l.ID
		meta := &lobbyMeta{Kind: "organised", Tournament: b.Tournament, CreatedBy: who.UID, CreatedByName: who.Name,
			Created: time.Now().UTC().Format(time.RFC3339)}
		for _, o := range b.Observers {
			meta.Observers = append(meta.Observers, observerMeta{UID: o.UID, Name: o.Name})
		}
		c.p.setMeta(s.ctx, key, meta)
		c.p.refreshSoon()
		log.Printf("lobby %s made by %s (FAF %d) for %s: %s, %d seats", key, who.Name, who.UID, orNone(b.Tournament), b.Map, len(b.Seats))
		st := &LobbyState{Key: key, Host: c.p.h.cfg.Name, Lobby: doc.Lobby, Meta: meta, Updated: time.Now().UTC().Format(time.RFC3339)}
		answer := map[string]any{"ok": true, "lobby": viewLobby(cfg, who, st)}
		if pl != nil {
			pl.Picked = c.p.h.cfg.Name
			answer["placement"] = pl
			log.Printf("lobby %s placed by ping: %s", key, pl.Basis)
		}
		writeJSON(w, http.StatusOK, answer)
		return
	}
	refuse(http.StatusConflict, fmt.Errorf("no host took the lobby: %s", strings.Join(reasons, "; ")))
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// operatorOps are the lobby server's control operations an organiser may send (docs/SERVER_DASHBOARD.md).
var operatorOps = []string{"force_start", "pause", "resume", "eject", "set_options", "set_player", "allow", "disallow",
	"substitute", "extend_timeouts", "end", "approve_observer", "refuse_observer"}

// /api/v1/lobbies/<host>/<id>[/ops/<op> | /armies]
func (s *server) lobbyRoute(w http.ResponseWriter, r *http.Request, cfg *Config, who Principal, rest string) {
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		fail(w, http.StatusNotFound, errors.New("a lobby is /api/v1/lobbies/<host>/<id>"))
		return
	}
	hostName, id, sub := parts[0], parts[1], ""
	if len(parts) == 3 {
		sub = parts[2]
	}
	key := hostName + "/" + id
	st, err := s.cachedLobby(r.Context(), key)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	if st == nil {
		fail(w, http.StatusNotFound, fmt.Errorf("no lobby %s", key))
		return
	}
	p := s.reg.get(hostName)
	switch {
	case sub == "" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lobby": viewLobby(cfg, who, st)})
	case sub == "" && r.Method == http.MethodDelete:
		if !canOperate(cfg, who, st.Meta) && !isOwner(who, st.Meta) {
			fail(w, http.StatusForbidden, errForbidden)
			return
		}
		if p == nil {
			fail(w, http.StatusNotFound, fmt.Errorf("no host %q", hostName))
			return
		}
		code, resp, err := p.h.call(r.Context(), http.MethodDelete, "/api/v1/lobbies/"+url.PathEscape(id), nil)
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		if code != http.StatusOK {
			fail(w, code, fmt.Errorf("host %s: %s", hostName, hostError(resp)))
			return
		}
		log.Printf("lobby %s stopped by %s (FAF %d)", key, who.Name, who.UID)
		p.refreshSoon()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case strings.HasPrefix(sub, "ops/") && r.Method == http.MethodPost:
		op := strings.TrimPrefix(sub, "ops/")
		if !canOperate(cfg, who, st.Meta) {
			fail(w, http.StatusForbidden, errForbidden)
			return
		}
		if !slices.Contains(operatorOps, op) {
			fail(w, http.StatusBadRequest, fmt.Errorf("no op %q (ops: %s)", op, strings.Join(operatorOps, ", ")))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			body = []byte("{}")
		}
		if !json.Valid(body) {
			fail(w, http.StatusBadRequest, errors.New("an op's fields are a JSON object"))
			return
		}
		s.passThrough(w, r, p, hostName, http.MethodPost, "/api/v1/lobbies/"+url.PathEscape(id)+"/api/v1/ops/"+op, body)
		log.Printf("lobby %s: %s by %s (FAF %d)", key, op, who.Name, who.UID)
		if p != nil {
			p.refreshSoon()
		}
	case sub == "armies" && r.Method == http.MethodGet:
		// Every army's economy and units: for those who run the game only (a player would see the enemy's).
		if !canOperate(cfg, who, st.Meta) {
			fail(w, http.StatusForbidden, errForbidden)
			return
		}
		s.passThrough(w, r, p, hostName, http.MethodGet, "/api/v1/lobbies/"+url.PathEscape(id)+"/api/v1/armies", nil)
	default:
		fail(w, http.StatusNotFound, fmt.Errorf("no %s %s", r.Method, r.URL.Path))
	}
}

// passThrough sends a request to the host and answers with the host's answer as it came.
func (s *server) passThrough(w http.ResponseWriter, r *http.Request, p *poller, hostName, method, path string, body []byte) {
	if p == nil {
		fail(w, http.StatusNotFound, fmt.Errorf("no host %q", hostName))
		return
	}
	code, resp, err := p.h.call(r.Context(), method, path, body)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

// /api/v1/hosts/<name>/{maps, settings, hint, plan, maps/<id>/preview.png}: what a lobby form needs, read from the
// host. Organisers and admins.
func (s *server) hostRead(w http.ResponseWriter, r *http.Request, cfg *Config, who Principal, rest string) {
	name, sub, _ := strings.Cut(rest, "/")
	p := s.reg.get(name)
	if p == nil {
		fail(w, http.StatusNotFound, fmt.Errorf("no host %q", name))
		return
	}
	if !who.Admin && !cfg.canOrganiseAny(who) {
		fail(w, http.StatusForbidden, errForbidden)
		return
	}
	switch {
	case sub == "" && r.Method == http.MethodGet:
		h, _ := p.state()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": h})
	case (sub == "maps" || sub == "settings" || sub == "hint") && r.Method == http.MethodGet:
		path := "/api/v1/" + sub
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
		s.passThrough(w, r, p, name, http.MethodGet, path, nil)
	case sub == "plan" && r.Method == http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
		if err != nil || !json.Valid(body) {
			fail(w, http.StatusBadRequest, errors.New("plan takes a JSON object"))
			return
		}
		s.passThrough(w, r, p, name, http.MethodPost, "/api/v1/plan", body)
	case strings.HasPrefix(sub, "maps/") && strings.HasSuffix(sub, "/preview.png") && r.Method == http.MethodGet:
		mapID := strings.TrimSuffix(strings.TrimPrefix(sub, "maps/"), "/preview.png")
		code, resp, err := p.h.call(r.Context(), http.MethodGet, "/api/v1/maps/"+url.PathEscape(mapID)+"/preview.png", nil)
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		if code != http.StatusOK {
			fail(w, code, errors.New(hostError(resp)))
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "private, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	default:
		fail(w, http.StatusNotFound, fmt.Errorf("no %s %s", r.Method, r.URL.Path))
	}
}
