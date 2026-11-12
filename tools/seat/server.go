package seat

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"faf-main/tools/gpgnet"
	"faf-main/tools/journal"
)

// The launch path of a game on a dedicated game server (plan WP12.2; docs/LAUNCHER_ADAPTER_CONTRACT.md, "Games on a
// game server"): the launcher gives the game one connection string, the server's address, this player's token and
// uid, and nothing about any other player. The engine's side is src/moho/app/ServerLobbyUi.cpp.
const (
	// DeliverGpgNet sends GPGNet's JoinServer in place of CreateLobby once the game reports Idle.
	DeliverGpgNet = "gpgnet"
	// DeliverArgs puts /connectserver /servertoken /serveruid on the game's command line; the game ignores the
	// CreateLobby it then gets, as it would from an unchanged ICE adapter.
	DeliverArgs = "args"

	cmdJoinServer    = "JoinServer"
	cmdPeerFeatures  = "PeerFeatures"
	argServerToken   = "/servertoken"
	argFeaturesAsk   = "/gpgnetfeatures"
	featureServerBit = 5 // EPeerFeature::ServerSession (src/moho/net/PeerFeatures.h)
)

// ServerJoin puts a seat's game on a game server. It carries this seat's token only: a director builds one per seat
// and never hands a seat another's (plan WP2.9).
type ServerJoin struct {
	Address  string `json:"address"`  // the game server, IPv4 host:port
	Token    string `json:"token"`    // this player's admission token
	Delivery string `json:"delivery"` // DeliverGpgNet (default) or DeliverArgs
}

// args is what the game's command line gets: the ask for the build's features, and with DeliverArgs the connection
// string itself.
func (j *ServerJoin) args(uid int) []string {
	out := []string{argFeaturesAsk}
	if j.Delivery == DeliverArgs {
		out = append(out, "/connectserver", j.Address, argServerToken, j.Token, "/serveruid", strconv.Itoa(uid))
	}
	return out
}

// TokenTag names a token in records and logs without showing it: "token:" and the first 12 hex digits of its SHA-256.
func TokenTag(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "token:" + hex.EncodeToString(sum[:6])
}

// RedactArgs is a command line with the value after /servertoken replaced by its tag.
func RedactArgs(args []string) []string {
	out := append([]string(nil), args...)
	for i := 1; i < len(out); i++ {
		if strings.EqualFold(out[i-1], argServerToken) {
			out[i] = TokenTag(out[i])
		}
	}
	return out
}

// noteFeatures keeps what the game announced to its launcher (the engine's one peer announcement, sent over GPGNet
// when the command line asks with /gpgnetfeatures).
func (s *Seat) noteFeatures(m gpgnet.Message) {
	if m.Command != cmdPeerFeatures {
		return
	}
	mask, err := strconv.ParseUint(m.Str(0), 10, 64)
	if err != nil {
		s.emit(journal.Record{Kind: journal.Warn, UID: s.cfg.UID, Text: "PeerFeatures mask unreadable: " + m.Str(0)})
		return
	}
	s.mu.Lock()
	s.features, s.featuresKnown = mask, true
	s.mu.Unlock()
}

// joinServer answers the game's Idle with its own connection string, if the game said it can take one.
func (s *Seat) joinServer() {
	s.mu.Lock()
	mask, known := s.features, s.featuresKnown
	s.mu.Unlock()
	if !known || mask&(1<<featureServerBit) == 0 {
		s.emit(journal.Record{Kind: journal.Warn, UID: s.cfg.UID,
			Text: "the game didn't announce ServerSession (a build without server mode?); JoinServer not sent"})
		return
	}
	j := s.cfg.Server
	_ = s.Send(gpgnet.New(cmdJoinServer, j.Address, j.Token, s.cfg.UID))
}

// recordArgs is a message's arguments as the journal keeps them: a JoinServer's token as its tag.
func recordArgs(m gpgnet.Message) []any {
	if m.Command != cmdJoinServer || len(m.Args) < 2 {
		return m.Args
	}
	out := append([]any(nil), m.Args...)
	out[1] = TokenTag(m.Str(1))
	return out
}
