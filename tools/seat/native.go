package seat

import (
	"encoding/json"
	"fmt"

	"faf-main/tools/gpgnet"
	"faf-main/tools/journal"
)

// Native puts no adapter in front of the game (issue #274,
// docs/LAUNCHER_NATIVE_NETWORK.md): the game runs every peer link itself and
// the seat plays the changed FAF client's part. It hands the game the ICE
// servers, passes the lobby server's JoinGame / ConnectToPeer in the server's
// own form, and relays IceMsg between the seats of one run as the lobby
// server does, to native and adapter seats alike.
type Native struct {
	IceServers []map[string]any `json:"iceServers"`
	// Bind is passed as /nativenetbind: the address ICE host candidates use
	// (hosts that drop loopback UDP to sockets bound to 0.0.0.0).
	Bind       string `json:"bind,omitempty"`
	ForceRelay bool   `json:"forceRelay,omitempty"`
	// Bus is the run's IceMsg relay; set by the launcher (local seats only).
	Bus *ContractBus `json:"-"`
}

// nativeTarget delivers relayed IceMsg to a native seat's game.
type nativeTarget struct{ s *Seat }

func (t nativeTarget) iceMsg(from int, msg any) bool {
	text, ok := msg.(string)
	if !ok {
		b, err := json.Marshal(msg)
		if err != nil {
			return false
		}
		text = string(b)
	}
	return t.s.Send(gpgnet.New("IceMsg", from, text)) == nil
}

// nativeArgs is what the game gets on its command line in native mode.
func (n *Native) nativeArgs() []string {
	args := []string{"/nativenet"}
	if n.Bind != "" {
		args = append(args, "/nativenetbind", n.Bind)
	}
	if n.ForceRelay {
		args = append(args, "/nativenetrelay")
	}
	return args
}

// nativeOutgoing rewrites the director's shipped-form JoinGame / ConnectToPeer
// ([address, login, id]) into the lobby server's form, which the changed
// client passes on unchanged: JoinGame [login, id], ConnectToPeer [login, id,
// offer]. Of each pair the lower id offers, as in contract mode.
func (s *Seat) nativeOutgoing(m gpgnet.Message) gpgnet.Message {
	if len(m.Args) != 3 {
		return m
	}
	login, okLogin := m.Args[1].(string)
	remote, okID := m.Int(2)
	if !okLogin || !okID {
		return m
	}
	switch m.Command {
	case "JoinGame":
		return gpgnet.New("JoinGame", login, int32(remote))
	case "ConnectToPeer":
		offer := int32(0)
		if s.cfg.UID < int(remote) {
			offer = 1
		}
		return gpgnet.New("ConnectToPeer", login, int32(remote), offer)
	}
	return m
}

// nativeRemember keeps what the lobby server said about this game's peers, in
// the server's form. The server says it once, and a game started again needs it
// once more (issue #275).
func (s *Seat) nativeRemember(m gpgnet.Message) {
	switch m.Command {
	case "JoinGame", "ConnectToPeer", "DisconnectFromPeer":
	default:
		return
	}
	at := 1
	if m.Command == "DisconnectFromPeer" {
		at = 0
	}
	id, ok := m.Int(at)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.nativePeers[:0]
	for _, known := range s.nativePeers {
		if other, _ := known.Int(1); other != id {
			kept = append(kept, known)
		}
	}
	s.nativePeers = kept
	if m.Command != "DisconnectFromPeer" {
		s.nativePeers = append(s.nativePeers, m)
	}
}

// RejoinNative starts the game again as FAF's client would after a crash, with
// no adapter: peers is "player id=source,...". The game's links died with it, so
// when it connects it gets what it got the first time, and no lobby starts.
func (s *Seat) RejoinNative(peers string, source, keyOf int) error {
	if s.cfg.Native == nil {
		return fmt.Errorf("player %d: not in native mode", s.cfg.UID)
	}
	s.mu.Lock()
	s.nativeReturning = true
	s.mu.Unlock()
	return s.Rejoin(peers, source, keyOf, true)
}

// IsNative reports whether this seat runs with no adapter.
func (s *Seat) IsNative() bool { return s.cfg.Native != nil }

// nativeOnConnected sends a game coming back what it needs for new links.
func (s *Seat) nativeOnConnected() {
	s.mu.Lock()
	returning := s.nativeReturning
	s.nativeReturning = false
	peers := append([]gpgnet.Message(nil), s.nativePeers...)
	lobbyPort := s.lobbyPort
	s.mu.Unlock()
	if !returning {
		return
	}
	s.nativeIceServers()
	_ = s.Send(gpgnet.New("CreateLobby", 0, lobbyPort, s.cfg.Name, s.cfg.UID, 1))
	for _, m := range peers {
		_ = s.Send(m)
	}
}

// nativeIncoming handles what the game sends that the lobby server would act
// on: IceMsg [receiver, text] goes to the receiver's seat as IceMsg [sender,
// text].
func (s *Seat) nativeIncoming(m gpgnet.Message) {
	if m.Command != "IceMsg" || len(m.Args) != 2 {
		return
	}
	to, ok := m.Int(0)
	if !ok {
		return
	}
	text := m.Str(1)
	if !s.cfg.Native.Bus.deliver(s.cfg.UID, int(to), text) {
		s.emit(journal.Record{Kind: journal.Warn, UID: s.cfg.UID,
			Text: fmt.Sprintf("native: IceMsg for player %d not delivered", to)})
	}
}

// nativeIceServers is the launcher's IceServers message, sent before
// CreateLobby.
func (s *Seat) nativeIceServers() {
	servers := s.cfg.Native.IceServers
	if servers == nil {
		servers = []map[string]any{}
	}
	b, err := json.Marshal(servers)
	if err != nil {
		return
	}
	_ = s.Send(gpgnet.New("IceServers", string(b)))
}
