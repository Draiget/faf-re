// Package hub connects the machines of a multi-machine run. A hub server
// (cmd/mpemu-server) sits where every machine can reach it, on the LAN or
// on a remote host known by name, and everyone connects to it outbound, so
// NAT on any side does not matter:
//
//   - agents (one per test PC, `mpemu agent`) run seats for the players on
//     their machine and stream every journal record back;
//   - a director (`mpemu run` / `mpemu lobby`) drives the session, sending
//     commands to agents and receiving their records;
//   - the hub also runs the shared network services: the icebreaker
//     signalling API and TURN for ICE runs, and a latching UDP relay with
//     impairment for relay runs.
//
// Control traffic is JSON envelopes posted into named mailboxes on the hub's
// queue (package bus) and streamed out as server-sent events.
package hub

import (
	"time"

	"faf-main/tools/gpgnet"
	"faf-main/tools/journal"
	"faf-main/tools/seat"
)

// Envelope types.
const (
	TypeStart   = "start"   // director -> agent: start a seat (Seat set)
	TypeSend    = "send"    // director -> agent: GPGNet message to a seat's game
	TypeKill    = "kill"    // director -> agent: kill a seat's game
	TypeClose   = "close"   // director -> agent: tear a seat down
	TypeStarted = "started" // agent -> director: seat is up (Host, Port)
	TypeError   = "error"   // agent -> director: a command failed
	TypeRecord  = "record"  // agent or hub -> director: one journal record
)

// Envelope is one control message.
type Envelope struct {
	Type  string `json:"type"`
	Run   string `json:"run,omitempty"`
	Reply string `json:"reply,omitempty"` // mailbox answers go to
	UID   int    `json:"uid,omitempty"`
	Agent string `json:"agent,omitempty"`

	Seat   *seat.Config     `json:"seat,omitempty"`
	Cmd    string           `json:"cmd,omitempty"`
	Args   []gpgnet.WireArg `json:"args,omitempty"`
	Record *WireRecord      `json:"record,omitempty"`
	Host   string           `json:"host,omitempty"` // where other games reach this seat's game
	Port   int              `json:"port,omitempty"` // the seat's lobby port
	Error  string           `json:"error,omitempty"`
}

// WireRecord is a journal record whose GPGNet arguments keep their types.
type WireRecord struct {
	Time    time.Time        `json:"t"`
	Kind    string           `json:"kind"`
	Game    uint64           `json:"game,omitempty"`
	UID     int              `json:"uid,omitempty"`
	Peer    int              `json:"peer,omitempty"`
	Command string           `json:"cmd,omitempty"`
	Args    []gpgnet.WireArg `json:"args,omitempty"`
	Text    string           `json:"text,omitempty"`
	Data    any              `json:"data,omitempty"`
}

// ToWire prepares a record for the hub.
func ToWire(r journal.Record) *WireRecord {
	return &WireRecord{Time: r.Time, Kind: r.Kind, Game: r.Game, UID: r.UID, Peer: r.Peer,
		Command: r.Command, Args: gpgnet.EncodeArgs(r.Args), Text: r.Text, Data: r.Data}
}

// Record restores a journal record (sequence number unset).
func (w *WireRecord) Record() journal.Record {
	r := journal.Record{Time: w.Time, Kind: w.Kind, Game: w.Game, UID: w.UID, Peer: w.Peer,
		Command: w.Command, Text: w.Text, Data: w.Data}
	if len(w.Args) > 0 {
		r.Args = gpgnet.DecodeArgs(w.Args)
	}
	return r
}

// AgentBox is an agent's mailbox; RunBox a director's.
func AgentBox(name string) string { return "agent/" + name }

// RunBox is the mailbox a director of one run listens on.
func RunBox(run string) string { return "run/" + run }
