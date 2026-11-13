package main

import (
	"encoding/json"
)

// Who may do what with a lobby. Organised lobbies (made through the service for a tournament or none): admins, the
// global organisers, the tournament's organisers and whoever made it run them. Hosted lobbies (a player's request):
// the requesting player sees them whole and may stop them; the game itself is theirs to run from their lobby screen.
// Lobbies the service didn't make (e.g. from the host's dashboard): admins only.

func canOperate(cfg *Config, who Principal, m *lobbyMeta) bool {
	if who.Admin {
		return true
	}
	if m == nil || m.Kind != "organised" {
		return false
	}
	return (who.UID != 0 && m.CreatedBy == who.UID) || cfg.canOrganise(who, m.Tournament)
}

func isOwner(who Principal, m *lobbyMeta) bool {
	return m != nil && who.UID != 0 && m.CreatedBy == who.UID
}

func canSeeAll(cfg *Config, who Principal, m *lobbyMeta) bool {
	return canOperate(cfg, who, m) || isOwner(who, m)
}

type seatView struct {
	Seat    int    `json:"seat"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	UID     int    `json:"uid,omitempty"`
	AI      string `json:"ai,omitempty"`
	Faction int    `json:"faction"`
	Team    int    `json:"team"`
	Join    string `json:"join,omitempty"`
}

type observerView struct {
	Name    string `json:"name"`
	UID     int    `json:"uid,omitempty"`
	Referee bool   `json:"referee"`
	Watch   string `json:"watch,omitempty"`
}

type youView struct {
	Seat  int    `json:"seat,omitempty"`
	Join  string `json:"join,omitempty"`
	Watch string `json:"watch,omitempty"`
}

// lobbyView is a lobby as one viewer may see it. Join and watch lines are credentials: a viewer gets their own
// (`you`), and those who run the lobby get every one plus the host's whole record and the lobby server's status.
type lobbyView struct {
	Key           string          `json:"key"`
	Host          string          `json:"host"`
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	State         string          `json:"state"`
	Phase         string          `json:"phase"`
	Beat          int             `json:"beat"`
	Kind          string          `json:"kind"`    // tournament or custom, as the host has it
	Control       string          `json:"control"` // organiser or player
	Origin        string          `json:"origin"`  // organised, hosted, or host (made outside the service)
	Tournament    string          `json:"tournament,omitempty"`
	CreatedBy     *createdBy      `json:"created_by,omitempty"`
	Map           json.RawMessage `json:"map"`
	Options       map[string]any  `json:"options"`
	Seats         []seatView      `json:"seats"`
	Observers     []observerView  `json:"observers"`
	ObserverDelay float64         `json:"observer_delay_seconds"`
	Created       string          `json:"created"`
	StartedAt     string          `json:"started_at"`
	Exit          string          `json:"exit,omitempty"`
	Status        any             `json:"status,omitempty"`
	Stale         bool            `json:"stale"`
	Updated       string          `json:"updated"`
	You           *youView        `json:"you,omitempty"`
	CanOperate    bool            `json:"can_operate"`
	CanStop       bool            `json:"can_stop"`
	HostRecord    json.RawMessage `json:"host_record,omitempty"`
}

type createdBy struct {
	UID  int    `json:"uid"`
	Name string `json:"name"`
}

func viewLobby(cfg *Config, who Principal, s *LobbyState) lobbyView {
	l := s.parsed()
	all := canSeeAll(cfg, who, s.Meta)
	v := lobbyView{Key: s.Key, Host: s.Host, ID: l.ID, Name: l.Name, State: l.State, Phase: l.Phase, Beat: l.Beat,
		Kind: l.Kind, Control: l.Control, Origin: "host", Map: l.Map, Options: l.Options, ObserverDelay: l.ObserverDelay,
		Created: l.Created, StartedAt: l.StartedAt, Exit: l.Exit, Stale: s.Stale, Updated: s.Updated,
		CanOperate: canOperate(cfg, who, s.Meta), Seats: []seatView{}, Observers: []observerView{}}
	v.CanStop = v.CanOperate || isOwner(who, s.Meta)
	if v.Options == nil {
		v.Options = map[string]any{}
	}
	if s.Meta != nil {
		v.Origin, v.Tournament = s.Meta.Kind, s.Meta.Tournament
		v.CreatedBy = &createdBy{UID: s.Meta.CreatedBy, Name: s.Meta.CreatedByName}
	}
	you := &youView{}
	for _, seat := range l.Seats {
		sv := seatView{Seat: seat.Seat, Kind: seat.Kind, Name: seat.Name, UID: seat.UID, AI: seat.AI, Faction: seat.Faction, Team: seat.Team}
		if all {
			sv.Join = seat.Join
		}
		if who.UID != 0 && seat.UID == who.UID && seat.Kind == "human" {
			you.Seat, you.Join = seat.Seat, seat.Join
		}
		v.Seats = append(v.Seats, sv)
	}
	for i, o := range l.Observers {
		ov := observerView{Name: o.Name, Referee: o.Referee}
		if s.Meta != nil && i < len(s.Meta.Observers) {
			ov.UID = s.Meta.Observers[i].UID
		}
		if all {
			ov.Watch = o.Watch
		}
		if who.UID != 0 && ov.UID == who.UID {
			you.Watch = o.Watch
		}
		v.Observers = append(v.Observers, ov)
	}
	if you.Join != "" || you.Watch != "" || you.Seat != 0 {
		v.You = you
	}
	if all {
		v.HostRecord = s.Lobby
		if len(s.Status) > 0 {
			var st any
			_ = json.Unmarshal(s.Status, &st)
			v.Status = st
		}
	} else if len(s.Status) > 0 {
		v.Status = publicStatus(s.Status)
	}
	return v
}

// publicStatus keeps what every viewer may see of a lobby server's status: the phase and each seat's presence,
// readiness and ping (not its mods, load or network details).
func publicStatus(raw json.RawMessage) map[string]any {
	var st map[string]any
	if json.Unmarshal(raw, &st) != nil {
		return nil
	}
	out := map[string]any{}
	for _, k := range []string{"phase", "host", "beat", "paused", "started", "countdown_seconds"} {
		if v, ok := st[k]; ok {
			out[k] = v
		}
	}
	seats := []any{}
	if list, ok := st["seats"].([]any); ok {
		for _, x := range list {
			seat, ok := x.(map[string]any)
			if !ok {
				continue
			}
			s := map[string]any{}
			for _, k := range []string{"uid", "name", "joined", "loaded", "lost", "gone", "away", "ping_ms", "ready", "slot"} {
				if v, ok := seat[k]; ok {
					s[k] = v
				}
			}
			seats = append(seats, s)
		}
	}
	out["seats"] = seats
	return out
}

// hostView: organisers and admins see a host's machine and load; players its name, region, reachability, lobby
// count and whether it takes players' requests.
func hostView(cfg *Config, who Principal, h HostState) any {
	if who.Admin || cfg.canOrganiseAny(who) {
		return h
	}
	return map[string]any{"name": h.Name, "region": h.Region, "reachable": h.Reachable, "lobbies": h.Lobbies,
		"player_hosting": h.PlayerHosting && cfg.PlayerHosting}
}

// canOrganiseAny: an admin, a global organiser, or an organiser of some tournament.
func (cfg *Config) canOrganiseAny(who Principal) bool {
	for _, r := range cfg.roles(who) {
		if r == "organiser" {
			return true
		}
	}
	return false
}
