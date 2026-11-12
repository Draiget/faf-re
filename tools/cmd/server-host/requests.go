package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Players' requests (public, no admin token): with player hosting on, a player asks for a game on the pool: the map,
// the seats (themselves first, friends, AIs), the settings over the pool's defaults. It starts at once when it fits,
// else waits in the pool's queue. The answer carries a key, the requester's credential for following and cancelling it.

// RequestBody is POST /api/v1/public/requests's body.
type RequestBody struct {
	Player  string         `json:"player"`
	Map     string         `json:"map"`
	Seats   []Seat         `json:"seats"`
	Options map[string]any `json:"options"`
	Code    string         `json:"code"` // the access code, when the pool asks for one
}

// PlayerRequest is one request as the host keeps it.
type PlayerRequest struct {
	ID      string
	Player  string
	key     string
	ip      string
	created time.Time
	ended   time.Time
	state   string // queued, started, ended, refused, cancelled
	reason  string
	queueID string
	lobbyID string
	// The lobby as it was when it ended, for a lobby the operator has since forgotten.
	last *ClaimLobby
}

// RequestView is a request as its player sees it.
type RequestView struct {
	ID       string      `json:"id"`
	Key      string      `json:"key"`
	Player   string      `json:"player"`
	State    string      `json:"state"` // queued, starting, lobby, game, ended, refused, cancelled
	Position *int        `json:"position"`
	Reason   *string     `json:"reason"`
	Lobby    *ClaimLobby `json:"lobby"`
	Created  string      `json:"created"`
}

// ClaimLobby is a player's lobby as its host player sees it: every human seat's join line to hand out.
type ClaimLobby struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	State   string         `json:"state"`
	Phase   string         `json:"phase"`
	Beat    int            `json:"beat"`
	Map     LobbyMap       `json:"map"`
	Seats   []Seat         `json:"seats"`
	Options map[string]any `json:"options"`
	Port    int            `json:"port"`
	// The placement's warnings, e.g. fewer cores than the game's worst moments need.
	Warnings []Warning `json:"warnings"`
}

const (
	requestsPerMinute = 6
	requestKeep       = 6 * time.Hour // ended requests are forgotten after this
)

func terminal(state string) bool {
	return state == "ended" || state == "refused" || state == "cancelled"
}

// setEnded ends a request that hasn't ended yet; the caller holds mu.
func (r *PlayerRequest) setEnded(state, reason string) {
	if terminal(r.state) {
		return
	}
	r.state, r.reason, r.ended = state, reason, time.Now()
}

func claimLobbyOf(l *Lobby) *ClaimLobby {
	return &ClaimLobby{ID: l.ID, Name: l.Name, State: l.State, Phase: l.Phase, Beat: l.Beat, Map: l.Map, Seats: l.Seats, Options: l.Options,
		Port: l.Port, Warnings: append([]Warning{}, l.Warnings...)}
}

// requestView builds a request's view; the caller holds mu.
func (m *manager) requestView(r *PlayerRequest) *RequestView {
	v := &RequestView{ID: r.ID, Key: r.key, Player: r.Player, State: r.state, Created: r.created.UTC().Format(time.RFC3339)}
	if r.reason != "" {
		reason := r.reason
		v.Reason = &reason
	}
	if r.state == "queued" {
		for _, q := range m.queue {
			if q.requestID == r.ID {
				p := m.positionLocked(q.ID)
				v.Position = &p
			}
		}
	}
	if l, ok := m.lobbies[r.lobbyID]; ok && r.lobbyID != "" {
		v.Lobby = claimLobbyOf(m.snapshot(l))
		if r.state == "started" {
			v.State = "ended"
			if running(l.State) {
				v.State = l.State
			}
		}
	} else if r.last != nil {
		v.Lobby = r.last
	}
	if v.State == "started" { // its lobby is gone from the list
		v.State = "ended"
	}
	return v
}

// requestEnded runs when a request's lobby ends; the caller holds mu.
func (m *manager) requestEnded(l *Lobby) {
	if l.Request == nil {
		return
	}
	r := m.requests[*l.Request]
	if r == nil {
		return
	}
	r.last = claimLobbyOf(m.snapshot(l))
	reason := ""
	if l.State == "failed" {
		reason = "the game's server ended: " + l.Exit
	}
	r.setEnded("ended", reason)
}

// lobbyEnded runs when a lobby's server ends: its request ends, and the queue may start what now fits. The caller
// holds mu.
func (m *manager) lobbyEnded(l *Lobby) {
	m.requestEnded(l)
	m.kick()
}

// allowAttempt counts a public request attempt from ip: at most requestsPerMinute a minute. The caller holds mu.
func (m *manager) allowAttempt(ip string, now time.Time) bool {
	for k, times := range m.rate {
		kept := times[:0]
		for _, t := range times {
			if now.Sub(t) < time.Minute {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(m.rate, k)
		} else {
			m.rate[k] = kept
		}
	}
	if len(m.rate[ip]) >= requestsPerMinute {
		return false
	}
	m.rate[ip] = append(m.rate[ip], now)
	return true
}

// submitRequest takes a player's request: checks it, queues it on the pool and starts what fits; the answer is the
// request started, queued, or refused.
func (m *manager) submitRequest(body RequestBody, ip string) (*RequestView, int, error) {
	now := time.Now()
	m.mu.Lock()
	allowed := m.allowAttempt(ip, now)
	pool := m.pool.clone()
	m.mu.Unlock()
	if !allowed {
		return nil, http.StatusTooManyRequests, fmt.Errorf("at most %d requests a minute from one address", requestsPerMinute)
	}
	if !pool.Enabled {
		return nil, http.StatusForbidden, errors.New("player hosting is off on this host")
	}
	if pool.Access == "code" && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(body.Code)), []byte(pool.Code)) != 1 {
		return nil, http.StatusForbidden, errors.New("wrong access code")
	}
	player := strings.TrimSpace(body.Player)
	if player == "" || len(player) > 40 {
		return nil, http.StatusBadRequest, errors.New("player is your name, 1..40 characters")
	}
	if err := validateOptions(body.Options); err != nil {
		return nil, http.StatusBadRequest, err
	}
	seats := append([]Seat(nil), body.Seats...)
	if len(seats) == 0 {
		seats = []Seat{{Kind: "human"}}
	}
	if len(seats) > pool.MaxPlayers {
		return nil, http.StatusBadRequest, fmt.Errorf("player games take up to %d players here, not %d", pool.MaxPlayers, len(seats))
	}
	if seats[0].Kind != "human" {
		return nil, http.StatusBadRequest, errors.New("seat 1 is the requesting player's: a human")
	}
	if seats[0].Name == "" {
		seats[0].Name = player
	}
	options := map[string]any{}
	for k, v := range pool.Options {
		options[k] = v
	}
	for k, v := range body.Options {
		options[k] = v
	}
	req := CreateRequest{Name: player + "'s game", Map: body.Map, Options: options, Seats: seats, Control: "player", Kind: "custom",
		LobbyMinutes: pool.LobbyMinutes}
	check := req.clone()
	mp, err := m.validate(&check)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	// A game larger than the whole pool would wait forever.
	cores := pool.Cores
	if cores == 0 {
		cores = estimateFor(len(seats), mp.KM).SuggestedCores
	}
	if cores > len(pool.CPUs) {
		return nil, http.StatusBadRequest, fmt.Errorf("this game takes %d cores and the player pool has %d CPUs", cores, len(pool.CPUs))
	}

	m.pumpMu.Lock()
	m.mu.Lock()
	for _, r := range m.requests {
		if r.ip == ip && strings.EqualFold(r.Player, player) && !terminal(m.requestView(r).State) {
			m.mu.Unlock()
			m.pumpMu.Unlock()
			return nil, http.StatusConflict, fmt.Errorf("%s already has a request here (%s); cancel it or wait for its game to end", player, r.ID)
		}
	}
	r := &PlayerRequest{ID: "r" + strconv.Itoa(m.nextRequest), Player: player, key: randomHex(16), ip: ip, created: now, state: "queued"}
	m.nextRequest++
	m.requests[r.ID] = r
	m.mu.Unlock()
	q, code, err := m.enqueueLocked(req, "pool", r.ID, player)
	if err != nil {
		m.mu.Lock()
		delete(m.requests, r.ID)
		m.mu.Unlock()
		m.pumpMu.Unlock()
		return nil, code, err
	}
	r.queueID = q.ID
	m.pumpLocked()
	status := http.StatusOK
	m.mu.Lock()
	q.fresh = false // from now on it has waited
	if r.state == "queued" {
		if pos := m.positionLocked(q.ID); pos > pool.MaxQueue {
			m.removeLocked(q.ID)
			r.setEnded("refused", fmt.Sprintf("no room in the player pool now, and its queue is full (%d waiting)", pool.MaxQueue))
			status = http.StatusConflict
		}
	}
	v := m.requestView(r)
	m.mu.Unlock()
	m.pumpMu.Unlock()
	switch {
	case v.State == "refused":
		log.Printf("request %s from %s (%s): refused: %s", r.ID, player, ip, r.reason)
		if status == http.StatusOK {
			status = http.StatusConflict
		}
	case v.State == "queued" && v.Position != nil:
		log.Printf("request %s from %s (%s): %s queued at %d", r.ID, player, ip, mp.Name, *v.Position)
	default:
		log.Printf("request %s from %s (%s): %s started as lobby %s", r.ID, player, ip, mp.Name, r.lobbyID)
	}
	return v, status, nil
}

// requestByKey finds a request by id and key; the caller holds mu.
func (m *manager) requestByKey(id, key string) *PlayerRequest {
	r := m.requests[id]
	if r == nil || len(key) == 0 || subtle.ConstantTimeCompare([]byte(r.key), []byte(key)) != 1 {
		return nil
	}
	return r
}

var errNoRequest = errors.New("no request with this id and key")

func (m *manager) getRequest(id, key string) (*RequestView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.requestByKey(id, key)
	if r == nil {
		return nil, errNoRequest
	}
	return m.requestView(r), nil
}

// cancelRequest is the player's cancel: out of the queue, or its lobby stopped before the game starts.
func (m *manager) cancelRequest(id, key string) (*RequestView, int, error) {
	m.pumpMu.Lock()
	m.mu.Lock()
	r := m.requestByKey(id, key)
	if r == nil {
		m.mu.Unlock()
		m.pumpMu.Unlock()
		return nil, http.StatusNotFound, errNoRequest
	}
	view := m.requestView(r)
	switch view.State {
	case "queued":
		m.removeLocked(r.queueID)
		r.setEnded("cancelled", "cancelled by the player")
		v := m.requestView(r)
		m.mu.Unlock()
		m.pumpMu.Unlock()
		m.kick()
		log.Printf("request %s cancelled by its player while queued", r.ID)
		return v, http.StatusOK, nil
	case "starting", "lobby":
		lobby := r.lobbyID
		r.setEnded("cancelled", "cancelled by the player")
		m.mu.Unlock()
		m.pumpMu.Unlock()
		log.Printf("request %s cancelled by its player: stopping lobby %s", r.ID, lobby)
		if _, err := m.stop(lobby); err != nil && !errors.Is(err, errNoLobby) {
			return nil, http.StatusInternalServerError, err
		}
		v, _ := m.getRequest(id, key)
		return v, http.StatusOK, nil
	case "game":
		m.mu.Unlock()
		m.pumpMu.Unlock()
		return view, http.StatusConflict, errors.New("the game has started: it ends in the game")
	default:
		m.mu.Unlock()
		m.pumpMu.Unlock()
		return view, http.StatusConflict, fmt.Errorf("this request has already ended (%s)", view.State)
	}
}

// pruneRequests forgets requests that ended long ago.
func (m *manager) pruneRequests(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.requests {
		if terminal(r.state) && !r.ended.IsZero() && now.Sub(r.ended) > requestKeep {
			delete(m.requests, id)
		}
	}
}

// clientIP is the address a public request came from: the connection's, or behind a proxy on this machine the one
// the proxy saw (the last X-Forwarded-For entry, which the proxy appends).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {
				return last
			}
		}
	}
	return host
}
