package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// hostClient talks to one server-host's REST API with its admin token.
type hostClient struct {
	cfg    HostConfig
	http   *http.Client // with a timeout
	stream *http.Client // without one, for event streams
}

func newHostClient(cfg HostConfig) *hostClient {
	return &hostClient{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}, stream: &http.Client{}}
}

// call sends one request; err is only for a host that didn't answer. The body is the host's JSON as it came.
func (h *hostClient) call(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.cfg.URL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.cfg.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("host %s didn't answer: %w", h.cfg.Name, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("host %s: %w", h.cfg.Name, err)
	}
	return resp.StatusCode, b, nil
}

// getJSON GETs path and decodes a 200 answer into out; any other answer is an error naming the host's reason.
func (h *hostClient) getJSON(ctx context.Context, path string, out any) error {
	code, b, err := h.call(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("host %s: %s answered %d: %s", h.cfg.Name, path, code, hostError(b))
	}
	return json.Unmarshal(b, out)
}

func hostError(b []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return e.Error
	}
	return strings.TrimSpace(string(b))
}

// HostState is a host as the service last saw it.
type HostState struct {
	Name          string  `json:"name"`
	Region        string  `json:"region"`
	Reachable     bool    `json:"reachable"`
	Error         string  `json:"error,omitempty"`
	Machine       string  `json:"machine,omitempty"` // the host's own name
	CPUModel      string  `json:"cpu_model,omitempty"`
	CPUs          int     `json:"cpus"`
	Nodes         int     `json:"nodes"`
	Load          float64 `json:"load"` // mean CPU load over the last 10 s, %
	MemoryTotalMB int     `json:"memory_total_mb"`
	MemoryFreeMB  int     `json:"memory_available_mb"`
	Lobbies       int     `json:"lobbies"` // running
	PlayerHosting bool    `json:"player_hosting"`
	PoolQueued    int     `json:"pool_queued"`
	PoolGames     int     `json:"pool_games"`
	PoolMaxGames  int     `json:"pool_max_games"`
	RTTEcho       string  `json:"rtt_echo,omitempty"` // where players probe its ping (plan WPR.16)
	Checked       string  `json:"checked"`
}

// lobbyMeta is what the service knows of a lobby it made: whose it is and for which tournament.
type lobbyMeta struct {
	Kind          string         `json:"kind"` // organised or hosted (a player's request)
	Tournament    string         `json:"tournament,omitempty"`
	CreatedBy     int            `json:"created_by"`
	CreatedByName string         `json:"created_by_name"`
	Created       string         `json:"created"`
	Observers     []observerMeta `json:"observers,omitempty"` // in the host's observer order
}

type observerMeta struct {
	UID  int    `json:"uid"`
	Name string `json:"name"`
}

// LobbyState is a lobby as the service caches it: the host's lobby record as it came, the lobby server's status
// while it runs, and the service's own record of it.
type LobbyState struct {
	Key     string          `json:"key"` // <host>/<lobby id>
	Host    string          `json:"host"`
	Lobby   json.RawMessage `json:"lobby"`
	Status  json.RawMessage `json:"status,omitempty"`
	Meta    *lobbyMeta      `json:"meta,omitempty"`
	Stale   bool            `json:"stale"` // the host didn't answer at the last poll
	Updated string          `json:"updated"`
}

// hostLobby is the part of the host's lobby record the service reads.
type hostLobby struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	State     string          `json:"state"`
	Phase     string          `json:"phase"`
	Beat      int             `json:"beat"`
	Kind      string          `json:"kind"`
	Control   string          `json:"control"`
	Side      string          `json:"side"`
	Request   *string         `json:"request"`
	Created   string          `json:"created"`
	StartedAt string          `json:"started_at"`
	Map       json.RawMessage `json:"map"`
	Options   map[string]any  `json:"options"`
	Seats     []struct {
		Seat    int    `json:"seat"`
		Kind    string `json:"kind"`
		Name    string `json:"name"`
		UID     int    `json:"uid"`
		AI      string `json:"ai"`
		Faction int    `json:"faction"`
		Team    int    `json:"team"`
		Join    string `json:"join"`
	} `json:"seats"`
	Observers []struct {
		Name    string `json:"name"`
		Referee bool   `json:"referee"`
		Watch   string `json:"watch"`
	} `json:"observers"`
	ObserverDelay float64 `json:"observer_delay_seconds"`
	Exit          string  `json:"exit"`
}

func (s *LobbyState) parsed() hostLobby {
	var l hostLobby
	_ = json.Unmarshal(s.Lobby, &l)
	return l
}

func runningState(state string) bool {
	return state == "starting" || state == "lobby" || state == "game"
}

// event is one message on the store's channel, and (redacted per viewer) one SSE event to web clients.
type event struct {
	Type  string          `json:"type"` // host, lobby, lobby_removed, lobby_event, host_removed
	Key   string          `json:"key,omitempty"`
	Host  *HostState      `json:"host,omitempty"`
	Lobby *LobbyState     `json:"lobby,omitempty"`
	Event string          `json:"event,omitempty"` // a lobby_event's name, as the lobby server sends it
	Data  json.RawMessage `json:"data,omitempty"`
	Meta  *lobbyMeta      `json:"meta,omitempty"` // a lobby_event's lobby's record, for who may see it
}

const eventsChannel = "events"

// lobbyTTL keeps a lobby's cached state alive between polls; a host that stops answering keeps its lobbies (stale).
const lobbyTTL = 2 * time.Minute

// poller follows one host: its summary, pool and lobbies every poll interval (sooner when kicked), each running
// lobby's status, and each running lobby's event stream relayed as lobby_event.
type poller struct {
	h        *hostClient
	store    Store
	interval time.Duration
	kick     chan struct{}

	mu      sync.Mutex
	host    HostState
	lobbies map[string]*LobbyState // by key
	sigs    map[string]string      // what was last published, per key
	hostSig string
	streams map[string]context.CancelFunc
	meta    map[string]*lobbyMeta
	maps    []hostMap
	mapsAt  time.Time
	pending []event // changes found under mu, published in order by flush
}

type hostMap struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	KM      int    `json:"km"`
	Players int    `json:"players"`
}

func newPoller(h *hostClient, store Store, interval time.Duration) *poller {
	return &poller{h: h, store: store, interval: interval, kick: make(chan struct{}, 1),
		host: HostState{Name: h.cfg.Name, Region: h.cfg.Region}, lobbies: map[string]*LobbyState{}, sigs: map[string]string{},
		streams: map[string]context.CancelFunc{}, meta: map[string]*lobbyMeta{}}
}

func (p *poller) refreshSoon() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *poller) run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		p.poll(ctx)
		select {
		case <-ctx.Done():
			p.mu.Lock()
			for _, cancel := range p.streams {
				cancel()
			}
			p.mu.Unlock()
			return
		case <-t.C:
		case <-p.kick:
		}
	}
}

func (p *poller) publish(ctx context.Context, e event) {
	b, _ := json.Marshal(e)
	if err := p.store.Publish(ctx, eventsChannel, string(b)); err != nil {
		log.Printf("publish %s %s: %v", e.Type, e.Key, err)
	}
}

func (p *poller) state() (HostState, []*LobbyState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*LobbyState, 0, len(p.lobbies))
	for _, l := range p.lobbies {
		c := *l
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return p.host, out
}

// setMeta records the service's own record of a lobby (or of a lobby still to be seen).
func (p *poller) setMeta(ctx context.Context, key string, m *lobbyMeta) {
	b, _ := json.Marshal(m)
	if err := p.store.Set(ctx, "meta:"+key, string(b), 30*24*time.Hour); err != nil {
		log.Printf("meta %s: %v", key, err)
	}
	p.mu.Lock()
	p.meta[key] = m
	p.mu.Unlock()
}

func (p *poller) metaOf(ctx context.Context, key string) *lobbyMeta {
	p.mu.Lock()
	m, ok := p.meta[key]
	p.mu.Unlock()
	if ok {
		return m
	}
	var out *lobbyMeta
	if s, found, err := p.store.Get(ctx, "meta:"+key); err == nil && found {
		out = &lobbyMeta{}
		if json.Unmarshal([]byte(s), out) != nil {
			out = nil
		}
	} else if err != nil {
		return nil // try again at the next poll
	}
	p.mu.Lock()
	p.meta[key] = out
	p.mu.Unlock()
	return out
}

// signature is a lobby's state without what changes at every poll (its live CPU and memory use), so that only real
// changes are pushed.
func signature(s *LobbyState) string {
	var l map[string]any
	_ = json.Unmarshal(s.Lobby, &l)
	delete(l, "usage")
	delete(l, "cpus_allowed")
	var st map[string]any
	_ = json.Unmarshal(s.Status, &st)
	if seats, ok := st["seats"].([]any); ok {
		for _, x := range seats {
			if seat, ok := x.(map[string]any); ok {
				for _, k := range []string{"camera_updates", "backlog_kb", "behind_beats"} {
					delete(seat, k)
				}
				// Pings move every poll; changes under 20 ms aren't news.
				if v, ok := seat["ping_ms"].(float64); ok {
					seat["ping_ms"] = math.Round(v / 20)
				}
			}
		}
	}
	b, _ := json.Marshal([]any{l, st, s.Meta, s.Stale})
	return string(b)
}

func (p *poller) poll(ctx context.Context) {
	now := time.Now().UTC().Format(time.RFC3339)
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	hs := HostState{Name: p.h.cfg.Name, Region: p.h.cfg.Region, Checked: now}
	var hostDoc struct {
		Host struct {
			Name     string `json:"name"`
			CPUModel string `json:"cpu_model"`
			Memory   struct {
				Total     int `json:"total"`
				Available int `json:"available"`
			} `json:"memory_mb"`
			CPUs []struct {
				Load10 float64 `json:"load10"`
			} `json:"cpus"`
			Nodes   []json.RawMessage `json:"nodes"`
			Lobbies int               `json:"lobbies"`
			RTTEcho string            `json:"rtt_echo"`
		} `json:"host"`
	}
	var lobbiesDoc struct {
		Lobbies []json.RawMessage `json:"lobbies"`
	}
	var poolDoc struct {
		Pool struct {
			Enabled  bool `json:"enabled"`
			MaxGames int  `json:"max_games"`
		} `json:"pool"`
		Usage struct {
			Games  int `json:"games"`
			Queued int `json:"queued"`
		} `json:"usage"`
	}
	err := p.h.getJSON(pctx, "/api/v1/host", &hostDoc)
	if err == nil {
		err = p.h.getJSON(pctx, "/api/v1/lobbies", &lobbiesDoc)
	}
	if err == nil {
		err = p.h.getJSON(pctx, "/api/v1/pool", &poolDoc)
	}
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		hs.Error = err.Error()
		p.mu.Lock()
		for key, l := range p.lobbies {
			l.Stale = true
			p.saveLocked(ctx, key, l)
		}
		p.mu.Unlock()
	} else {
		hs.Reachable = true
		hs.Machine, hs.CPUModel = hostDoc.Host.Name, hostDoc.Host.CPUModel
		hs.CPUs, hs.Nodes, hs.Lobbies = len(hostDoc.Host.CPUs), len(hostDoc.Host.Nodes), hostDoc.Host.Lobbies
		hs.MemoryTotalMB, hs.MemoryFreeMB = hostDoc.Host.Memory.Total, hostDoc.Host.Memory.Available
		sum := 0.0
		for _, c := range hostDoc.Host.CPUs {
			sum += c.Load10
		}
		if len(hostDoc.Host.CPUs) > 0 {
			hs.Load = math.Round(sum/float64(len(hostDoc.Host.CPUs))*10) / 10
		}
		hs.PlayerHosting, hs.PoolMaxGames = poolDoc.Pool.Enabled, poolDoc.Pool.MaxGames
		hs.PoolGames, hs.PoolQueued = poolDoc.Usage.Games, poolDoc.Usage.Queued
		p.updateLobbies(ctx, pctx, lobbiesDoc.Lobbies, now)
	}
	// The echo players probe: the configuration's, else what the host says (kept while it doesn't answer).
	switch {
	case p.h.cfg.RTTEcho != "":
		hs.RTTEcho = p.h.cfg.RTTEcho
	case err == nil:
		hs.RTTEcho = hostDoc.Host.RTTEcho
	default:
		p.mu.Lock()
		hs.RTTEcho = p.host.RTTEcho
		p.mu.Unlock()
	}
	p.flush(ctx)
	// The host's summary: stored every poll, pushed when more than its load moved (or the load by 5 points).
	hb, _ := json.Marshal(hs)
	if err := p.store.Set(ctx, "host:"+hs.Name, string(hb), lobbyTTL); err != nil {
		log.Printf("store host %s: %v", hs.Name, err)
	}
	sigHost := hs
	sigHost.Checked, sigHost.Load = "", math.Round(hs.Load/5)
	sb, _ := json.Marshal(sigHost)
	p.mu.Lock()
	p.host = hs
	changed := string(sb) != p.hostSig
	p.hostSig = string(sb)
	p.mu.Unlock()
	if changed {
		p.publish(ctx, event{Type: "host", Key: hs.Name, Host: &hs})
	}
}

// flush publishes the changes found so far, in the order they were found.
func (p *poller) flush(ctx context.Context) {
	p.mu.Lock()
	evs := p.pending
	p.pending = nil
	p.mu.Unlock()
	for _, e := range evs {
		p.publish(ctx, e)
	}
}

// saveLocked writes a lobby's state to the store and pushes it when it changed; the caller holds mu.
func (p *poller) saveLocked(ctx context.Context, key string, l *LobbyState) {
	b, _ := json.Marshal(l)
	if err := p.store.Set(ctx, "lobby:"+key, string(b), lobbyTTL); err != nil {
		log.Printf("store lobby %s: %v", key, err)
	}
	sig := signature(l)
	if sig != p.sigs[key] {
		p.sigs[key] = sig
		c := *l
		p.pending = append(p.pending, event{Type: "lobby", Key: key, Lobby: &c})
	}
}

func (p *poller) updateLobbies(ctx, pctx context.Context, raws []json.RawMessage, now string) {
	seen := map[string]bool{}
	for _, raw := range raws {
		var l hostLobby
		if json.Unmarshal(raw, &l) != nil || l.ID == "" {
			continue
		}
		key := p.h.cfg.Name + "/" + l.ID
		seen[key] = true
		st := &LobbyState{Key: key, Host: p.h.cfg.Name, Lobby: raw, Updated: now, Meta: p.metaOf(ctx, key)}
		if st.Meta == nil && l.Request != nil {
			st.Meta = p.requestMeta(ctx, *l.Request)
		}
		p.mu.Lock()
		prev := p.lobbies[key]
		p.mu.Unlock()
		if l.State == "lobby" || l.State == "game" {
			var status json.RawMessage
			if err := p.h.getJSON(pctx, "/api/v1/lobbies/"+url.PathEscape(l.ID)+"/api/v1/status", &status); err == nil {
				st.Status = status
			} else if prev != nil {
				st.Status = prev.Status
			}
		}
		p.mu.Lock()
		p.lobbies[key] = st
		p.saveLocked(ctx, key, st)
		// The lobby server's events, relayed while it runs.
		if _, on := p.streams[key]; (l.State == "lobby" || l.State == "game") && !on {
			sctx, cancel := context.WithCancel(ctx)
			p.streams[key] = cancel
			go p.follow(sctx, key, l.ID)
		} else if on && !runningState(l.State) {
			p.streams[key]()
			delete(p.streams, key)
		}
		p.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for key := range p.lobbies {
		if seen[key] {
			continue
		}
		delete(p.lobbies, key)
		delete(p.sigs, key)
		if cancel, ok := p.streams[key]; ok {
			cancel()
			delete(p.streams, key)
		}
		_ = p.store.Del(ctx, "lobby:"+key)
		p.pending = append(p.pending, event{Type: "lobby_removed", Key: key})
	}
}

// requestMeta is the record of a player's request the service sent (a hosted lobby's owner), if it sent it.
func (p *poller) requestMeta(ctx context.Context, requestID string) *lobbyMeta {
	s, ok, err := p.store.Get(ctx, "request:"+p.h.cfg.Name+"/"+requestID)
	if err != nil || !ok {
		return nil
	}
	var r playerRequest
	if json.Unmarshal([]byte(s), &r) != nil {
		return nil
	}
	return &lobbyMeta{Kind: "hosted", CreatedBy: r.UID, CreatedByName: r.Name, Created: r.Created}
}

// follow relays a running lobby's server events (through the host's proxy) until ctx ends, reconnecting after 2 s.
func (p *poller) follow(ctx context.Context, key, id string) {
	for ctx.Err() == nil {
		err := p.followOnce(ctx, key, id)
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("events of %s: %v", key, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (p *poller) followOnce(ctx context.Context, key, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.h.cfg.URL+"/api/v1/lobbies/"+url.PathEscape(id)+"/api/v1/events", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.h.cfg.token)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := p.h.stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	name, data := "", ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if data != "" {
				p.relay(ctx, key, name, data)
			}
			name, data = "", ""
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			d := strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
			if data != "" {
				data += "\n"
			}
			data += d
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.EOF
}

func (p *poller) relay(ctx context.Context, key, name, data string) {
	if name == "" {
		name = "message"
	}
	raw := json.RawMessage(data)
	if !json.Valid(raw) {
		b, _ := json.Marshal(data)
		raw = b
	}
	p.mu.Lock()
	var m *lobbyMeta
	if l, ok := p.lobbies[key]; ok {
		m = l.Meta
	}
	p.mu.Unlock()
	p.publish(ctx, event{Type: "lobby_event", Key: key, Event: name, Data: raw, Meta: m})
	if name != "log" && name != "stats" {
		p.refreshSoon() // the lobby's state changed: read it now rather than at the next tick
	}
}

// mapList is the host's maps, read at most every 5 minutes.
func (p *poller) mapList(ctx context.Context) ([]hostMap, error) {
	p.mu.Lock()
	maps, at := p.maps, p.mapsAt
	p.mu.Unlock()
	if maps != nil && time.Since(at) < 5*time.Minute {
		return maps, nil
	}
	var doc struct {
		Maps []hostMap `json:"maps"`
	}
	if err := p.h.getJSON(ctx, "/api/v1/maps", &doc); err != nil {
		return maps, err
	}
	p.mu.Lock()
	p.maps, p.mapsAt = doc.Maps, time.Now()
	p.mu.Unlock()
	return doc.Maps, nil
}

// registry is every configured host's poller.
type registry struct {
	store    Store
	mu       sync.Mutex
	pollers  map[string]*poller
	cancels  map[string]context.CancelFunc
	configs  map[string]HostConfig
	interval time.Duration
}

func newRegistry(store Store) *registry {
	return &registry{store: store, pollers: map[string]*poller{}, cancels: map[string]context.CancelFunc{},
		configs: map[string]HostConfig{}}
}

// apply starts pollers for new or changed hosts and stops those of removed or changed ones.
func (r *registry) apply(ctx context.Context, hosts []HostConfig, interval time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	want := map[string]HostConfig{}
	for _, h := range hosts {
		want[h.Name] = h
	}
	for name, cfg := range r.configs {
		if w, ok := want[name]; ok && w == cfg && interval == r.interval {
			continue
		}
		r.cancels[name]()
		_, lobbies := r.pollers[name].state()
		delete(r.pollers, name)
		delete(r.cancels, name)
		delete(r.configs, name)
		if _, still := want[name]; !still {
			for _, l := range lobbies {
				_ = r.store.Del(ctx, "lobby:"+l.Key)
				b, _ := json.Marshal(event{Type: "lobby_removed", Key: l.Key})
				_ = r.store.Publish(ctx, eventsChannel, string(b))
			}
			_ = r.store.Del(ctx, "host:"+name)
			b, _ := json.Marshal(event{Type: "host_removed", Key: name})
			_ = r.store.Publish(ctx, eventsChannel, string(b))
		}
	}
	r.interval = interval
	for name, cfg := range want {
		if _, ok := r.pollers[name]; ok {
			continue
		}
		p := newPoller(newHostClient(cfg), r.store, interval)
		pctx, cancel := context.WithCancel(ctx)
		r.pollers[name], r.cancels[name], r.configs[name] = p, cancel, cfg
		go p.run(pctx)
	}
}

func (r *registry) get(name string) *poller {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pollers[name]
}

func (r *registry) all() []*poller {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*poller, 0, len(r.pollers))
	for _, p := range r.pollers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].h.cfg.Name < out[j].h.cfg.Name })
	return out
}

func (r *registry) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.cancels {
		c()
	}
}
