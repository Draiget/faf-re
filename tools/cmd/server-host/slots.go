package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Plan WP17.18: open slots, capacity held for players who host their own game next to the operator's tournament
// lobbies. The operator makes a slot (players, map size, CPUs, default settings); its CPUs count as taken from then
// on. A player claims it with its claim code, picking the map, the seats and the settings; the slot becomes a
// player-hosted lobby on the slot's CPUs (MatchLobbyControl "player": the host changes the game options in their own
// lobby screen). When that game ends the slot opens again with a new code, unless it was made not to.

// Slot is one open slot, as the operator sees it.
type Slot struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	State        string         `json:"state"` // open, claimed, lobby, game, ended
	MaxPlayers   int            `json:"max_players"`
	KM           int            `json:"km"`
	CPUs         []int          `json:"cpus"`
	Nodes        []int          `json:"nodes"`
	Warnings     []Warning      `json:"warnings"`
	ClaimCode    string         `json:"claim_code,omitempty"`
	Lobby        *string        `json:"lobby"`
	HostPlayer   *string        `json:"host_player"`
	LobbyMinutes float64        `json:"lobby_minutes"`
	Options      map[string]any `json:"options"`
	Reopen       bool           `json:"reopen"`
	Games        int            `json:"games"` // games hosted on it so far
	Created      string         `json:"created"`
}

// SlotRequest is POST /api/v1/slots's body.
type SlotRequest struct {
	Name         string          `json:"name"`
	MaxPlayers   int             `json:"max_players"`
	KM           int             `json:"km"` // the largest map expected, for the estimate (default 20)
	Cores        int             `json:"cores"`
	CPUs         json.RawMessage `json:"cpus"`
	LobbyMinutes float64         `json:"lobby_minutes"`
	Count        int             `json:"count"`
	Options      map[string]any  `json:"options"`
	Force        bool            `json:"force"`
	Reopen       *bool           `json:"reopen"` // default true
}

// ClaimRequest is POST /api/v1/claim/<code>'s body: the player's own game.
type ClaimRequest struct {
	Player         string         `json:"player"`
	Map            string         `json:"map"`
	Seats          []Seat         `json:"seats"`
	Options        map[string]any `json:"options"`
	StartWhenReady float64        `json:"start_when_ready"`
}

// validateOptions checks game options as a request gives them.
func validateOptions(options map[string]any) error {
	for k, v := range options {
		if !reOptionKey.MatchString(k) || fixedOptions[k] {
			return fmt.Errorf("game option %q can't be set", k)
		}
		switch value := v.(type) {
		case string:
			if len(value) > 64 || strings.ContainsAny(value, "\n\r") {
				return fmt.Errorf("game option %s: value too long or not one line", k)
			}
		case float64, bool:
		default:
			return fmt.Errorf("game option %s: a string, number or true/false", k)
		}
	}
	return nil
}

// parseCPUs reads a request's "cpus": a list of ids, or "auto" / nothing.
func parseCPUs(raw json.RawMessage) ([]int, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == `"auto"` || text == "null" {
		return nil, nil
	}
	var ids []int
	if err := json.Unmarshal(raw, &ids); err != nil || len(ids) == 0 {
		return nil, errors.New(`cpus is a list of CPU ids or "auto"`)
	}
	return ids, nil
}

// slotState is what a slot shows: its own state, or its lobby's once claimed. The caller holds mu.
func (m *manager) slotState(s *Slot) string {
	if s.State == "claiming" {
		return "claimed"
	}
	if s.Lobby == nil {
		return s.State
	}
	l, ok := m.lobbies[*s.Lobby]
	if !ok {
		return s.State
	}
	switch l.State {
	case "starting":
		return "claimed"
	case "lobby", "game":
		return l.State
	}
	return s.State
}

func (m *manager) slotSnapshot(s *Slot) *Slot {
	c := *s
	c.State = m.slotState(s)
	c.CPUs = append([]int(nil), s.CPUs...)
	c.Nodes = append([]int(nil), s.Nodes...)
	c.Warnings = append([]Warning{}, s.Warnings...)
	c.Options = map[string]any{}
	for k, v := range s.Options {
		c.Options[k] = v
	}
	return &c
}

// holding is true while a slot keeps its CPUs without a lobby of its own on them (open, or being claimed).
func holding(s *Slot) bool { return s.State == "open" || s.State == "claiming" }

func (m *manager) createSlots(req SlotRequest) ([]*Slot, int, error) {
	if req.Count == 0 {
		req.Count = 1
	}
	if req.MaxPlayers == 0 {
		req.MaxPlayers = 8
	}
	if req.KM == 0 {
		req.KM = 20
	}
	if req.LobbyMinutes == 0 {
		req.LobbyMinutes = 60
	}
	switch {
	case req.Count < 1 || req.Count > 16:
		return nil, http.StatusBadRequest, errors.New("count is 1..16")
	case req.MaxPlayers < 1 || req.MaxPlayers > kMaxPlayers:
		return nil, http.StatusBadRequest, fmt.Errorf("max_players is 1..%d", kMaxPlayers)
	case req.KM < 1 || req.KM > 100:
		return nil, http.StatusBadRequest, errors.New("km is 1..100")
	case req.LobbyMinutes < 1 || req.LobbyMinutes > 24*60:
		return nil, http.StatusBadRequest, errors.New("lobby_minutes is 1..1440")
	case len(req.Name) > 40:
		return nil, http.StatusBadRequest, errors.New("name too long")
	case req.Cores < 0 || req.Cores > 64:
		return nil, http.StatusBadRequest, errors.New("cores is 0 (the suggestion) to 64")
	}
	if err := validateOptions(req.Options); err != nil {
		return nil, http.StatusBadRequest, err
	}
	cpus, err := parseCPUs(req.CPUs)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if req.Name == "" {
		req.Name = "Open slot"
	}
	reopen := req.Reopen == nil || *req.Reopen

	m.mu.Lock()
	live := 0
	for _, l := range m.lobbies {
		if running(l.State) {
			live++
		}
	}
	for _, s := range m.slots {
		if holding(s) {
			live++
		}
	}
	m.mu.Unlock()
	if live+req.Count > m.cfg.maxLobbies {
		return nil, http.StatusConflict, fmt.Errorf("this host runs at most %d lobbies and open slots, %d are in use", m.cfg.maxLobbies, live)
	}

	var made []*Slot
	undo := func() {
		m.mu.Lock()
		for _, s := range made {
			delete(m.slots, s.ID)
		}
		m.mu.Unlock()
	}
	for i := 0; i < req.Count; i++ {
		// Each slot is placed with the ones before it already holding their CPUs, so Auto spreads them.
		plan := place(m.machine(), PlanRequest{Players: req.MaxPlayers, KM: req.KM, Cores: req.Cores, CPUs: cpus})
		if (!plan.Fits && !req.Force) || len(plan.CPUs) == 0 {
			undo()
			var why []string
			for _, w := range plan.Warnings {
				if w.Severity == "error" {
					why = append(why, w.Text)
				}
			}
			return nil, http.StatusConflict, fmt.Errorf("slot %d of %d doesn't fit (force to make it anyway): %s", i+1, req.Count, strings.Join(why, "; "))
		}
		name := req.Name
		if req.Count > 1 {
			name = fmt.Sprintf("%s %d", req.Name, i+1)
		}
		options := map[string]any{}
		for k, v := range req.Options {
			options[k] = v
		}
		m.mu.Lock()
		s := &Slot{ID: "s" + strconv.Itoa(m.nextSlot), Name: name, State: "open", MaxPlayers: req.MaxPlayers, KM: req.KM,
			CPUs: plan.CPUs, Nodes: plan.Nodes, Warnings: plan.Warnings, ClaimCode: randomHex(8), LobbyMinutes: req.LobbyMinutes,
			Options: options, Reopen: reopen, Created: time.Now().UTC().Format(time.RFC3339)}
		m.nextSlot++
		m.slots[s.ID] = s
		made = append(made, m.slotSnapshot(s))
		m.mu.Unlock()
	}
	return made, http.StatusOK, nil
}

func (m *manager) listSlots() []*Slot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Slot, 0, len(m.slots))
	for _, s := range m.slots {
		out = append(out, m.slotSnapshot(s))
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.Atoi(out[i].ID[1:])
		b, _ := strconv.Atoi(out[j].ID[1:])
		return a < b
	})
	return out
}

var errNoSlot = errors.New("no such slot")

// deleteSlot frees an open slot, or stops the game on a claimed one; either way the slot is gone.
func (m *manager) deleteSlot(id string) error {
	m.mu.Lock()
	s, ok := m.slots[id]
	if !ok {
		m.mu.Unlock()
		return errNoSlot
	}
	delete(m.slots, id)
	var lobby string
	if s.Lobby != nil {
		lobby = *s.Lobby
	}
	m.mu.Unlock()
	if lobby != "" {
		if _, err := m.stop(lobby); err != nil && !errors.Is(err, errNoLobby) {
			return err
		}
	}
	return nil
}

// slotByCode finds the slot a claim code belongs to; the caller holds mu.
func (m *manager) slotByCode(code string) *Slot {
	if len(code) < 8 {
		return nil
	}
	for _, s := range m.slots {
		if s.ClaimCode != "" && subtle.ConstantTimeCompare([]byte(s.ClaimCode), []byte(code)) == 1 {
			return s
		}
	}
	return nil
}

// ClaimView is what a claim code shows its player: the slot, and once claimed the lobby with every seat's join line.
type ClaimView struct {
	Slot struct {
		ID           string         `json:"id"`
		Name         string         `json:"name"`
		State        string         `json:"state"`
		MaxPlayers   int            `json:"max_players"`
		KM           int            `json:"km"`
		Cores        int            `json:"cores"`
		LobbyMinutes float64        `json:"lobby_minutes"`
		Options      map[string]any `json:"options"`
	} `json:"slot"`
	Lobby *ClaimLobby `json:"lobby"`
}

// ClaimLobby is the claimed lobby as its host player sees it.
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
	// The placement's warnings, e.g. a map larger than the slot was sized for.
	Warnings []Warning `json:"warnings"`
}

func (m *manager) claimView(code string) (*ClaimView, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.slotByCode(code)
	if s == nil {
		return nil, false
	}
	v := &ClaimView{}
	v.Slot.ID, v.Slot.Name, v.Slot.State = s.ID, s.Name, m.slotState(s)
	v.Slot.MaxPlayers, v.Slot.KM, v.Slot.Cores, v.Slot.LobbyMinutes = s.MaxPlayers, s.KM, len(s.CPUs), s.LobbyMinutes
	v.Slot.Options = map[string]any{}
	for k, val := range s.Options {
		v.Slot.Options[k] = val
	}
	if s.Lobby != nil {
		if l, ok := m.lobbies[*s.Lobby]; ok {
			c := m.snapshot(l)
			v.Lobby = &ClaimLobby{ID: c.ID, Name: c.Name, State: c.State, Phase: c.Phase, Beat: c.Beat, Map: c.Map, Seats: c.Seats, Options: c.Options, Port: c.Port, Warnings: append([]Warning{}, c.Warnings...)}
		}
	}
	return v, true
}

// claim turns an open slot into the player's lobby, on the slot's CPUs.
func (m *manager) claim(code string, req ClaimRequest) (*ClaimView, int, error) {
	req.Player = strings.TrimSpace(req.Player)
	if req.Player == "" || len(req.Player) > 40 {
		return nil, http.StatusBadRequest, errors.New("player is your name, 1..40 characters")
	}
	if err := validateOptions(req.Options); err != nil {
		return nil, http.StatusBadRequest, err
	}
	m.mu.Lock()
	s := m.slotByCode(code)
	if s == nil || s.State != "open" {
		m.mu.Unlock()
		if s == nil {
			return nil, http.StatusNotFound, errors.New("no slot has this claim code")
		}
		if s.State == "ended" {
			return nil, http.StatusConflict, errors.New("this slot's game has ended and it doesn't open again")
		}
		return nil, http.StatusConflict, errors.New("this slot is already claimed")
	}
	s.State = "claiming" // nobody else claims it meanwhile; its CPUs stay held
	slot := *s
	m.mu.Unlock()
	release := func() {
		m.mu.Lock()
		if s.State == "claiming" {
			s.State = "open"
		}
		m.mu.Unlock()
	}

	seats := req.Seats
	if len(seats) == 0 {
		seats = []Seat{{Kind: "human"}}
	}
	if len(seats) > slot.MaxPlayers {
		release()
		return nil, http.StatusBadRequest, fmt.Errorf("this slot takes up to %d players, not %d", slot.MaxPlayers, len(seats))
	}
	if seats[0].Kind != "human" {
		release()
		return nil, http.StatusBadRequest, errors.New("seat 1 is the host's: a human")
	}
	if seats[0].Name == "" {
		seats[0].Name = req.Player
	}
	options := map[string]any{}
	for k, v := range slot.Options {
		options[k] = v
	}
	for k, v := range req.Options {
		options[k] = v
	}
	cpus, _ := json.Marshal(slot.CPUs)
	// The operator accepted the slot's CPUs when making it, so the claim isn't refused for them (Force); a map larger
	// than the slot was sized for shows as the lobby's warning.
	l, code2, err := m.createIn(CreateRequest{Name: slot.Name + ": " + req.Player, Map: req.Map, Options: options, Seats: seats,
		Control: "player", StartWhenReady: req.StartWhenReady, LobbyMinutes: slot.LobbyMinutes, CPUs: cpus, Force: true}, slot.ID)
	if err != nil {
		release()
		return nil, code2, err
	}
	m.mu.Lock()
	if cur, ok := m.slots[slot.ID]; ok && cur == s {
		id, player := l.ID, req.Player
		s.State, s.Lobby, s.HostPlayer = "claimed", &id, &player
		s.Games++
	}
	m.mu.Unlock()
	v, _ := m.claimView(code)
	return v, http.StatusOK, nil
}

// lobbyEnded runs when a lobby's server ends; a slot's lobby opens its slot again with a new code, or ends it. The
// caller holds mu.
func (m *manager) lobbyEnded(l *Lobby) {
	if l.Slot == "" {
		return
	}
	s, ok := m.slots[l.Slot]
	if !ok || s.Lobby == nil || *s.Lobby != l.ID {
		return
	}
	if s.Reopen {
		s.State, s.Lobby, s.HostPlayer, s.ClaimCode = "open", nil, nil, randomHex(8)
		return
	}
	// The code keeps working, so its player sees the slot ended rather than an unknown code.
	s.State = "ended"
}
