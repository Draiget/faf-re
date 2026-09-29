// Package scenario describes and runs multiplayer test scenarios: which
// players to start, how they connect, what to do to the network while they
// play, and what must (not) have happened by the end.
package scenario

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"faf-main/tools/launcher"
	"faf-main/tools/relay"
)

// Scenario is one YAML file.
type Scenario struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Timeout bounds the whole run (default 15m).
	Timeout time.Duration `yaml:"timeout"`

	launcher.Config `yaml:",inline"`

	Steps  []Step `yaml:"steps"`
	Expect Expect `yaml:"expect"`
}

// UIDs is a player selector: a uid, a list of uids, or "all" / "others"
// (others = everyone but the host).
type UIDs struct {
	All    bool
	Others bool
	List   []int
}

// UnmarshalYAML accepts 3, [1, 2], "all" and "others".
func (u *UIDs) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		switch strings.ToLower(n.Value) {
		case "all", "*":
			u.All = true
			return nil
		case "others":
			u.Others = true
			return nil
		}
		v, err := strconv.Atoi(n.Value)
		if err != nil {
			return fmt.Errorf("line %d: %q is not a uid, list, \"all\" or \"others\"", n.Line, n.Value)
		}
		u.List = []int{v}
		return nil
	case yaml.SequenceNode:
		return n.Decode(&u.List)
	}
	return fmt.Errorf("line %d: bad uid selector", n.Line)
}

// Resolve expands the selector against the run's players.
func (u UIDs) Resolve(all []int, host int) []int {
	switch {
	case u.All:
		return append([]int(nil), all...)
	case u.Others:
		var out []int
		for _, id := range all {
			if id != host {
				out = append(out, id)
			}
		}
		return out
	}
	return u.List
}

// Step is one action; exactly one field is set.
type Step struct {
	// Start brings players up (endpoint, adapter, game).
	Start *UIDs `yaml:"start"`
	// Host sends HostGame to one player once it is in the lobby.
	Host int `yaml:"host"`
	// Join connects players to the host and to each other.
	Join *UIDs `yaml:"join"`
	// WaitState blocks until players report a GameState.
	WaitState *WaitState `yaml:"waitState"`
	// WaitMessage blocks until a GPGNet message arrives.
	WaitMessage *Match `yaml:"waitMessage"`
	// Wait sleeps.
	Wait time.Duration `yaml:"wait"`
	// Link changes a relay link's impairment.
	Link *LinkStep `yaml:"link"`
	// Isolate cuts every link of a player; Restore undoes it.
	Isolate int `yaml:"isolate"`
	Restore int `yaml:"restore"`
	// Kill terminates games (and adapters), as a crash would.
	Kill *UIDs `yaml:"kill"`
	// Send delivers a raw GPGNet message to a game.
	Send *SendStep `yaml:"send"`
	// Check evaluates expectations now, failing the run if they do not hold.
	Check *Expect `yaml:"check"`
	// Interactive hands control to the console until "continue" or "quit".
	Interactive bool `yaml:"interactive"`
	// Note writes a marker into the journal.
	Note string `yaml:"note"`
}

// WaitState waits for players to reach a state.
type WaitState struct {
	UIDs    UIDs          `yaml:"uids"`
	State   string        `yaml:"state"`
	Timeout time.Duration `yaml:"timeout"`
}

// LinkStep impairs traffic between two players (ModeRelay).
type LinkStep struct {
	From             int  `yaml:"from"`
	To               int  `yaml:"to"`
	OneWay           bool `yaml:"oneWay"`
	relay.Impairment `yaml:",inline"`
}

// SendStep is a raw GPGNet message.
type SendStep struct {
	UID  int    `yaml:"uid"`
	Cmd  string `yaml:"cmd"`
	Args []any  `yaml:"args"`
}

// Match selects journal records.
type Match struct {
	UID     int           `yaml:"uid"`  // 0: any player
	Kind    string        `yaml:"kind"` // default gpgnet.in
	Cmd     string        `yaml:"cmd"`
	Arg     string        `yaml:"arg"` // substring of any argument
	Timeout time.Duration `yaml:"timeout"`
}

// Expect lists assertions; zero values are not checked.
type Expect struct {
	// AllLaunched: every player reported GameState Launching.
	AllLaunched bool `yaml:"allLaunched"`
	// NoDesync: no game reported a Desync.
	NoDesync bool `yaml:"noDesync"`
	// NoCrash: no game or adapter exited unless mpemu killed it.
	NoCrash bool `yaml:"noCrash"`
	// Present / Absent: journal records that must / must not exist.
	Present []Match `yaml:"present"`
	Absent  []Match `yaml:"absent"`
	// PeerStats checks what the fake game measured on every link.
	PeerStats *PeerStatsExpect `yaml:"peerStats"`
	// MinTurnAllocations: TURN relay was really used.
	MinTurnAllocations int `yaml:"minTurnAllocations"`
	// RelayOnly: every ICE candidate the adapters exchanged was a TURN relay
	// candidate (forced relay really forced).
	RelayOnly bool `yaml:"relayOnly"`
	// LogsAgree: the listed players' game logs hold the same matching lines.
	LogsAgree []LogsAgree `yaml:"logsAgree"`
}

// LogsAgree requires every listed player's game log (<run>/game-<uid>.log,
// so players on this machine only) to have at least one line matching
// Pattern, and the matches to be identical across players, in order. With
// capture groups only the groups are compared, so a line can carry
// per-client detail around the part that must agree.
type LogsAgree struct {
	UIDs    UIDs   `yaml:"uids"`
	Pattern string `yaml:"pattern"`
}

// PeerStatsExpect bounds the fakegame's per-peer measurements (its last
// report for each link).
type PeerStatsExpect struct {
	MinAnswered int           `yaml:"minAnswered"`
	MinAvgRTT   time.Duration `yaml:"minAvgRtt"`
	MaxAvgRTT   time.Duration `yaml:"maxAvgRtt"`
	// MaxLoss is the tolerated fraction of unanswered pings (0..1).
	MaxLoss *float64 `yaml:"maxLoss"`
	// MinLoss asserts that an impairment really dropped traffic.
	MinLoss float64 `yaml:"minLoss"`
}

// Load reads a scenario file.
func Load(path string) (*Scenario, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sc Scenario
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err = dec.Decode(&sc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if sc.Name == "" {
		sc.Name = strings.TrimSuffix(strings.TrimSuffix(baseName(path), ".yaml"), ".yml")
	}
	return &sc, nil
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// needsGames reports whether the step can only succeed with game instances
// running. Waiting, the console, notes, checks, kills and link changes can
// all still run (or be skipped) once every game has exited.
func (s Step) needsGames() bool {
	return s.Start != nil || s.Host != 0 || s.Join != nil || s.WaitState != nil ||
		s.WaitMessage != nil || s.Send != nil
}

// String describes a step for the journal.
func (s Step) String() string {
	switch {
	case s.Start != nil:
		return "start " + s.Start.String()
	case s.Host != 0:
		return fmt.Sprintf("host %d", s.Host)
	case s.Join != nil:
		return "join " + s.Join.String()
	case s.WaitState != nil:
		return fmt.Sprintf("waitState %s %s", s.WaitState.UIDs.String(), s.WaitState.State)
	case s.WaitMessage != nil:
		return fmt.Sprintf("waitMessage uid=%d cmd=%s arg=%q", s.WaitMessage.UID, s.WaitMessage.Cmd, s.WaitMessage.Arg)
	case s.Wait != 0:
		return "wait " + s.Wait.String()
	case s.Link != nil:
		return fmt.Sprintf("link %d->%d %+v", s.Link.From, s.Link.To, s.Link.Impairment)
	case s.Isolate != 0:
		return fmt.Sprintf("isolate %d", s.Isolate)
	case s.Restore != 0:
		return fmt.Sprintf("restore %d", s.Restore)
	case s.Kill != nil:
		return "kill " + s.Kill.String()
	case s.Send != nil:
		return fmt.Sprintf("send %d %s %v", s.Send.UID, s.Send.Cmd, s.Send.Args)
	case s.Check != nil:
		return "check"
	case s.Interactive:
		return "interactive"
	case s.Note != "":
		return "note " + s.Note
	}
	return "empty step"
}

func (u UIDs) String() string {
	switch {
	case u.All:
		return "all"
	case u.Others:
		return "others"
	}
	return fmt.Sprint(u.List)
}
