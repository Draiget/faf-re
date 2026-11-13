package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// playerRequest is a player's request for a game of their own, sent by the service to a host's player hosting (the
// host's public request API) in the signed-in player's name. Its key is the host's credential for the request; the
// service keeps it and never shows it.
type playerRequest struct {
	Host    string `json:"host"`
	ID      string `json:"id"`
	Key     string `json:"key"`
	UID     int    `json:"uid"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

const requestTTL = 7 * 24 * time.Hour

type requestBody struct {
	Host    string         `json:"host"`
	Region  string         `json:"region"`
	Map     string         `json:"map"`
	Seats   []seatIn       `json:"seats"`
	Options map[string]any `json:"options"`
}

// POST /api/v1/requests: a signed-in player asks for a game they host, on a host with player hosting on (the named
// one, or the one with the shortest queue, then the fewest games, then the least load). Seat 1 is the player.
func (s *server) submitRequest(w http.ResponseWriter, r *http.Request, cfg *Config, who Principal) {
	if !cfg.PlayerHosting {
		fail(w, http.StatusForbidden, errors.New("player hosting through this service is off"))
		return
	}
	if who.UID == 0 {
		fail(w, http.StatusForbidden, errors.New("a request is a FAF user's: sign in with FAF"))
		return
	}
	var b requestBody
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		fail(w, http.StatusBadRequest, fmt.Errorf("body: %w", err))
		return
	}
	if strings.TrimSpace(b.Map) == "" {
		fail(w, http.StatusBadRequest, errors.New("a request needs a map"))
		return
	}
	seats := b.Seats
	if len(seats) == 0 {
		seats = []seatIn{{Kind: "human"}}
	}
	if seats[0].Kind != "human" {
		fail(w, http.StatusBadRequest, errors.New("seat 1 is the requesting player's"))
		return
	}
	seats[0].UID, seats[0].Name = who.UID, who.Name
	for i := 1; i < len(seats); i++ {
		if seats[i].UID == who.UID {
			fail(w, http.StatusBadRequest, fmt.Errorf("seat %d: you are seat 1", i+1))
			return
		}
	}
	type option struct {
		p     *poller
		state HostState
	}
	opts := []option{}
	reasons := []string{}
	for _, p := range s.reg.all() {
		h, _ := p.state()
		if (b.Host != "" && p.h.cfg.Name != b.Host) || (b.Region != "" && h.Region != b.Region) {
			continue
		}
		if !h.Reachable || !h.PlayerHosting {
			reasons = append(reasons, p.h.cfg.Name+": doesn't take players' games now")
			continue
		}
		opts = append(opts, option{p, h})
	}
	sort.SliceStable(opts, func(i, j int) bool {
		a, c := opts[i].state, opts[j].state
		if a.PoolQueued != c.PoolQueued {
			return a.PoolQueued < c.PoolQueued
		}
		if a.PoolGames != c.PoolGames {
			return a.PoolGames < c.PoolGames
		}
		return a.Load < c.Load
	})
	if len(opts) == 0 {
		fail(w, http.StatusConflict, fmt.Errorf("no host takes players' games now: %s", orNone(strings.Join(reasons, "; "))))
		return
	}
	p := opts[0].p
	// The pool may ask for an access code; the service has the host's admin token and passes it on.
	var pool struct {
		Pool struct {
			Access string `json:"access"`
			Code   string `json:"code"`
		} `json:"pool"`
	}
	if err := p.h.getJSON(r.Context(), "/api/v1/pool", &pool); err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	forward := map[string]any{"player": who.Name, "map": b.Map, "seats": seats, "options": b.Options}
	if pool.Pool.Access == "code" {
		forward["code"] = pool.Pool.Code
	}
	body, _ := json.Marshal(forward)
	code, resp, err := p.h.call(r.Context(), http.MethodPost, "/api/v1/public/requests", body)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	var doc struct {
		Request map[string]any `json:"request"`
	}
	_ = json.Unmarshal(resp, &doc)
	if code != http.StatusOK || doc.Request == nil {
		if code == http.StatusOK {
			code = http.StatusBadGateway
		}
		fail(w, code, fmt.Errorf("host %s: %s", p.h.cfg.Name, hostError(resp)))
		return
	}
	id, _ := doc.Request["id"].(string)
	key, _ := doc.Request["key"].(string)
	if id == "" || key == "" {
		fail(w, http.StatusBadGateway, fmt.Errorf("host %s answered a request without id or key", p.h.cfg.Name))
		return
	}
	pr := playerRequest{Host: p.h.cfg.Name, ID: id, Key: key, UID: who.UID, Name: who.Name, Created: time.Now().UTC().Format(time.RFC3339)}
	rb, _ := json.Marshal(pr)
	full := pr.Host + "/" + pr.ID
	if err := s.store.Set(r.Context(), "request:"+full, string(rb), requestTTL); err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	_ = s.store.Set(r.Context(), "myrequest:"+strconv.Itoa(who.UID)+":"+full, "", requestTTL)
	p.refreshSoon()
	log.Printf("request %s by %s (FAF %d): %s, %d seats", full, who.Name, who.UID, b.Map, len(seats))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request": requestView(pr, doc.Request)})
}

// requestView is the host's request record without its key, with the service's id <host>/<id>.
func requestView(pr playerRequest, hostRec map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range hostRec {
		if k != "key" && k != "code" { // the request's credential and the pool's access code stay with the service
			out[k] = v
		}
	}
	out["host"], out["ref"] = pr.Host, pr.Host+"/"+pr.ID
	return out
}

func (s *server) ownRequest(r *http.Request, who Principal, ref string) (*playerRequest, error) {
	v, ok, err := s.store.Get(r.Context(), "request:"+ref)
	if err != nil {
		return nil, err
	}
	var pr playerRequest
	if !ok || json.Unmarshal([]byte(v), &pr) != nil || (pr.UID != who.UID && !who.Admin) {
		return nil, nil
	}
	return &pr, nil
}

// GET /api/v1/requests: the signed-in player's requests with their state on their hosts.
func (s *server) listRequests(w http.ResponseWriter, r *http.Request, who Principal) {
	keys, err := s.store.Keys(r.Context(), "myrequest:"+strconv.Itoa(who.UID)+":")
	if err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	out := []map[string]any{}
	for _, k := range keys {
		ref := k[strings.LastIndex(k, ":")+1:]
		pr, err := s.ownRequest(r, who, ref)
		if err != nil || pr == nil {
			continue
		}
		out = append(out, s.requestState(r, pr))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "requests": out})
}

// requestState asks the host for the request; a host that doesn't answer gives the service's record only.
func (s *server) requestState(r *http.Request, pr *playerRequest) map[string]any {
	p := s.reg.get(pr.Host)
	if p != nil {
		var doc struct {
			Request map[string]any `json:"request"`
		}
		path := "/api/v1/public/requests/" + url.PathEscape(pr.ID) + "?key=" + url.QueryEscape(pr.Key)
		if err := p.h.getJSON(r.Context(), path, &doc); err == nil && doc.Request != nil {
			return requestView(*pr, doc.Request)
		}
	}
	return map[string]any{"ref": pr.Host + "/" + pr.ID, "host": pr.Host, "id": pr.ID, "player": pr.Name,
		"state": "unknown", "created": pr.Created}
}

// /api/v1/requests/<host>/<id>: GET follows one, DELETE cancels it (out of the queue, or its lobby stopped before
// the game).
func (s *server) requestRoute(w http.ResponseWriter, r *http.Request, who Principal, ref string) {
	if strings.Count(ref, "/") != 1 {
		fail(w, http.StatusNotFound, errors.New("a request is /api/v1/requests/<host>/<id>"))
		return
	}
	pr, err := s.ownRequest(r, who, ref)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	if pr == nil {
		fail(w, http.StatusNotFound, fmt.Errorf("no request %s of yours", ref))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request": s.requestState(r, pr)})
	case http.MethodDelete:
		p := s.reg.get(pr.Host)
		if p == nil {
			fail(w, http.StatusNotFound, fmt.Errorf("no host %q", pr.Host))
			return
		}
		code, resp, err := p.h.call(r.Context(), http.MethodDelete,
			"/api/v1/public/requests/"+url.PathEscape(pr.ID)+"?key="+url.QueryEscape(pr.Key), nil)
		if err != nil {
			fail(w, http.StatusBadGateway, err)
			return
		}
		var doc struct {
			Request map[string]any `json:"request"`
		}
		_ = json.Unmarshal(resp, &doc)
		if code != http.StatusOK {
			fail(w, code, fmt.Errorf("host %s: %s", pr.Host, hostError(resp)))
			return
		}
		p.refreshSoon()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request": requestView(*pr, doc.Request)})
	default:
		fail(w, http.StatusMethodNotAllowed, errors.New("GET or DELETE"))
	}
}
