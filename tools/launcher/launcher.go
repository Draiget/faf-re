// Package launcher is the lobby-server half of the emulation: the director of
// a session. It decides who hosts and who joins (the FAF lobby server's
// full-mesh JoinGame / ConnectToPeer ordering), tells the remaining players
// when someone leaves, and composes the addresses games use to reach each
// other in every network mode. Each player's game runs in a seat (package
// seat) on this machine or, through an agent, on another one; the director
// only sees the journal records seats emit, and derives player state from
// them.
package launcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"faf-main/tools/gpgnet"
	"faf-main/tools/hub"
	"faf-main/tools/icebreaker"
	"faf-main/tools/journal"
	"faf-main/tools/procs"
	"faf-main/tools/relay"
	"faf-main/tools/seat"
	"faf-main/tools/turnsrv"
)

// Seat is a player's game as the director drives it: a seat in this process,
// or one on another machine reached through an agent.
type Seat interface {
	Start(ctx context.Context) error
	Send(m gpgnet.Message) error
	Kill()
	Close()
	LobbyPort() int
	Snapshot() seat.Snapshot
}

// Player is one seat at runtime, as the director sees it.
type Player struct {
	Cfg PlayerConfig

	seat Seat
	host string // address other games use to reach this one's lobby port

	mu        sync.Mutex
	state     string
	joined    bool
	connected bool
	external  bool
	live      bool // the game instance is running (external: its GPGNet link is up)
	wasLive   bool
}

// Gone reports whether the player's game ran and has since exited.
func (p *Player) Gone() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wasLive && !p.live
}

// State is the last GameState the game reported.
func (p *Player) State() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// Launcher directs one emulated FAF game session.
type Launcher struct {
	cfg Config
	j   *journal.Journal
	job *procs.Job

	relay *relay.Relay
	ice   *icebreaker.Server
	turn  *turnsrv.Server
	hub   *hubSession // players on other machines, or services on a remote hub

	players map[int]*Player
	order   []int

	mu       sync.Mutex
	hostUID  int
	closed   bool
	live     int // running game instances
	everLive bool
	gone     chan struct{} // closed when the last running instance exits
	goneOnce sync.Once
}

// New starts the run's services: the relay in ModeRelay, the icebreaker and
// TURN servers in ModeICE. No game is started yet.
func New(cfg Config, j *journal.Journal) (*Launcher, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if cfg.RunDir != "" {
		if err := os.MkdirAll(cfg.RunDir, 0o755); err != nil {
			return nil, err
		}
	}
	job, err := procs.NewJob()
	if err != nil {
		return nil, err
	}
	if cfg.RunID == "" {
		cfg.RunID = time.Now().Format("20060102-150405.000")
	}
	if cfg.Hub != "" {
		// A shared hub serves many runs: give this one its own game id.
		cfg.GameID = uint64(time.Now().UnixMilli() % 1_000_000_000_000)
	}
	localHost := "127.0.0.1"
	if cfg.anyRemote() {
		// Other machines must reach this machine's games.
		localHost = cfg.Advertise
		if localHost == "" {
			localHost = turnsrv.FirstPrivateIPv4().String()
		}
	}
	l := &Launcher{cfg: cfg, j: j, job: job, players: make(map[int]*Player), gone: make(chan struct{})}
	for _, pc := range cfg.Players {
		l.players[pc.UID] = &Player{Cfg: pc, host: localHost}
		l.order = append(l.order, pc.UID)
	}
	if cfg.Hub != "" {
		if err = l.openHub(); err != nil {
			job.Close()
			return nil, err
		}
	}

	switch {
	case cfg.Mode == ModeRelay && l.hub == nil:
		l.relay = relay.New(j, relay.Options{Default: cfg.Link})
	case cfg.Mode == ModeICE && l.hub == nil:
		if !cfg.ICE.NoTurn {
			l.turn, err = turnsrv.Start(turnsrv.Config{Port: cfg.TurnPort, PublicIP: cfg.TurnIP}, j)
			if err != nil {
				job.Close()
				return nil, err
			}
		}
		l.ice = icebreaker.New(icebreaker.Options{
			ForceRelay: cfg.ICE.ForceRelay,
			Turn:       l.turn,
			LogDir:     cfg.RunDir,
			State:      func() any { return l.Snapshot() },
		}, j)
		addr := cfg.HTTPAddr
		if addr == "" {
			addr = "127.0.0.1:0"
		}
		if err = l.ice.Start(addr); err != nil {
			l.closeServices()
			job.Close()
			return nil, err
		}
		turnAddr := "none"
		if l.turn != nil {
			turnAddr = l.turn.Addr()
		}
		j.Note(journal.Note, 0, fmt.Sprintf("icebreaker at %s, TURN at %s, forceRelay=%v",
			l.ice.URL(), turnAddr, cfg.ICE.ForceRelay), nil)
	}
	return l, nil
}

// Config returns the normalised configuration.
func (l *Launcher) Config() Config { return l.cfg }

// Journal is the run's journal.
func (l *Launcher) Journal() *journal.Journal { return l.j }

// Players lists uids in configuration order.
func (l *Launcher) Players() []int { return append([]int(nil), l.order...) }

// Player looks up a seat.
func (l *Launcher) Player(uid int) (*Player, error) {
	p := l.players[uid]
	if p == nil {
		return nil, fmt.Errorf("no player %d", uid)
	}
	return p, nil
}

// Host is the uid of the hosting player, 0 before Host.
func (l *Launcher) Host() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hostUID
}

// GamesGone is closed once every game instance that was started has exited
// on its own (spawned: the process ended; started by hand: its GPGNet link
// closed). Exits mpemu caused itself do not count.
func (l *Launcher) GamesGone() <-chan struct{} { return l.gone }

// record is where every seat's records enter the run: the director updates
// its view of the player first, then journals the record, then acts on it.
// That order is what WaitState relies on (state before record).
func (l *Launcher) record(r journal.Record) {
	after := l.observe(r)
	l.j.Add(r)
	if after != nil {
		after()
	}
}

// observe derives player state from a record; the returned action runs once
// the record is journaled.
func (l *Launcher) observe(r journal.Record) func() {
	p := l.players[r.UID]
	if p == nil {
		return nil
	}
	switch r.Kind {
	case journal.GpgIn:
		if r.Command == "GameState" && len(r.Args) > 0 {
			state, _ := r.Args[0].(string)
			p.mu.Lock()
			p.state = state
			p.mu.Unlock()
		}
	case journal.ProcStart:
		if r.Text == "game" {
			return l.liveAction(p, true, false)
		}
	case journal.ProcExit:
		if r.Text == "game" {
			data, _ := r.Data.(map[string]any)
			killed, _ := data["killedByMpemu"].(bool)
			return l.liveAction(p, false, killed)
		}
	case journal.ProcExternal:
		p.mu.Lock()
		p.external = true
		p.mu.Unlock()
	case journal.GpgConnect:
		p.mu.Lock()
		p.connected = true
		external := p.external
		p.mu.Unlock()
		if external {
			return l.liveAction(p, true, false) // no process to watch; the link is the instance
		}
	case journal.GpgClose:
		p.mu.Lock()
		p.connected = false
		external := p.external
		p.mu.Unlock()
		var live func()
		if external { // a spawned game's liveness follows its process instead
			live = l.liveAction(p, false, false)
		}
		return func() {
			l.onLeave(p)
			if live != nil {
				live()
			}
		}
	}
	return nil
}

// liveAction records a player's game coming up or going away. An exit mpemu
// caused itself (a scenario or console kill) never counts towards "every game
// has exited": a scenario may kill everyone and start them again.
func (l *Launcher) liveAction(p *Player, live, intentional bool) func() {
	l.mu.Lock()
	p.mu.Lock()
	changed := p.live != live
	p.live = live
	if live {
		p.wasLive = true
	}
	p.mu.Unlock()
	if !changed {
		l.mu.Unlock()
		return nil
	}
	if live {
		l.live++
		l.everLive = true
	} else {
		l.live--
	}
	allGone := !live && !intentional && l.live == 0 && l.everLive && !l.closed
	l.mu.Unlock()
	if !allGone {
		return nil
	}
	return func() {
		l.j.Note(journal.Note, 0, "every game instance has exited", nil)
		l.goneOnce.Do(func() { close(l.gone) })
	}
}

// seatConfig turns the run configuration into what one seat needs.
func (l *Launcher) seatConfig(p *Player) seat.Config {
	c, pc := l.cfg, p.Cfg
	exe := pc.Exe
	if exe == "" {
		exe = c.Game.Exe
	}
	sc := seat.Config{
		UID: pc.UID, Name: pc.Name, Team: pc.Team, StartSpot: pc.StartSpot, Faction: pc.Faction,
		Players: len(l.order), AutoLobby: c.Lobby == LobbyAuto, GameOptions: c.GameOption,
		Exe: exe, Dir: c.Game.Dir, Init: c.Game.Init,
		Args:   append(append([]string(nil), c.Game.Args...), pc.Args...),
		Window: c.Game.Window, NoSound: c.Game.NoSound, Prefs: c.Game.Prefs,
		Spawn:  boolOr(pc.Spawn, boolOr(c.Game.Spawn, true)),
		RunDir: c.RunDir,

		SaveReplay:   c.Game.SaveReplays,
		PrivateCache: takesCacheDir(exe),
	}
	if c.Game.Tile {
		// Cascade: each window's title bar stays visible and clickable.
		idx := sort.SearchInts(l.sortedUIDs(), pc.UID)
		sc.Position = []int{20 + idx*60, 20 + idx*60}
	}
	if c.Mode == ModeICE {
		sc.ICE = &seat.ICE{Adapter: c.ICE.Adapter, GameID: c.GameID,
			ForceRelay: c.ICE.ForceRelay, LogLevel: c.ICE.LogLevel}
		if l.hub != nil {
			sc.ICE.APIRoot, sc.ICE.Secret = l.hub.apiRoot, c.HubSecret
		} else {
			sc.ICE.APIRoot = l.ice.URL()
		}
	}
	return sc
}

func (l *Launcher) sortedUIDs() []int {
	s := append([]int(nil), l.order...)
	sort.Ints(s)
	return s
}

// Start brings a player up: its seat opens the GPGNet endpoint, starts the
// ICE adapter in ModeICE, then the game (or instructions to start it by hand).
func (l *Launcher) Start(ctx context.Context, uid int) error {
	p, err := l.Player(uid)
	if err != nil {
		return err
	}
	if p.seat == nil {
		if p.Cfg.Agent != "" {
			p.seat = &remoteSeat{l: l, uid: uid, agent: p.Cfg.Agent, cfg: l.seatConfig(p),
				replies: make(chan hub.Envelope, 4)}
		} else {
			s, err := seat.New(l.seatConfig(p), l.job, l.record)
			if err != nil {
				return err
			}
			p.seat = s
		}
	}
	return p.seat.Start(ctx)
}

// onLeave tells the remaining players a peer left, as the lobby server does.
func (l *Launcher) onLeave(p *Player) {
	uid := p.Cfg.UID
	p.mu.Lock()
	wasJoined := p.joined
	p.joined = false
	p.mu.Unlock()
	if !wasJoined {
		return
	}
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed || l.cfg.Leave == LeaveNever {
		return
	}
	if l.cfg.Leave == LeaveInLobby && l.anyLaunched() {
		return
	}
	for _, other := range l.order {
		if other == uid {
			continue
		}
		q := l.players[other]
		q.mu.Lock()
		connected := q.connected
		q.mu.Unlock()
		if connected {
			_ = l.send(q, gpgnet.New("DisconnectFromPeer", uid))
		}
	}
}

func (l *Launcher) anyLaunched() bool {
	for _, uid := range l.order {
		if s := l.players[uid].State(); s == "Launching" || s == "Ended" {
			return true
		}
	}
	return false
}

func (l *Launcher) send(p *Player, m gpgnet.Message) error {
	if p.seat == nil {
		return fmt.Errorf("player %d was never started", p.Cfg.UID)
	}
	return p.seat.Send(m)
}

// Send delivers an arbitrary GPGNet message to a player's game.
func (l *Launcher) Send(uid int, m gpgnet.Message) error {
	p, err := l.Player(uid)
	if err != nil {
		return err
	}
	return l.send(p, m)
}

// WaitState blocks until the player's game reports state. It fails at once
// when that game exits instead, rather than waiting out the timeout.
func (l *Launcher) WaitState(ctx context.Context, uid int, state string) error {
	return l.waitGameState(ctx, uid, fmt.Sprintf("GameState %q", state),
		func(s string) bool { return s == state })
}

// WaitLoaded blocks until the player's game reports its first GameState,
// which the engine sends only once its device and effects are loaded.
func (l *Launcher) WaitLoaded(ctx context.Context, uid int) error {
	return l.waitGameState(ctx, uid, "its first GameState", func(s string) bool { return s != "" })
}

// SharesCache reports whether the player's game is started by mpemu on this
// machine with the user's shared shader cache: the engine has no /cachedir.
// Such games must not load at the same time as one another.
func (l *Launcher) SharesCache(uid int) bool {
	p, err := l.Player(uid)
	if err != nil {
		return false
	}
	return p.Cfg.Agent == "" && boolOr(p.Cfg.Spawn, boolOr(l.cfg.Game.Spawn, true)) &&
		!takesCacheDir(l.seatConfig(p).Exe)
}

// takesCacheDir reports whether the engine accepts /cachedir. The retail
// ForgedAlliance.exe does not; the recovered main.exe builds do.
func takesCacheDir(exe string) bool {
	return !strings.EqualFold(filepath.Base(exe), "ForgedAlliance.exe")
}

// waitGameState blocks until the player's reported GameState satisfies want,
// failing at once when that game exits instead of waiting out ctx.
func (l *Launcher) waitGameState(ctx context.Context, uid int, what string, want func(state string) bool) error {
	p, err := l.Player(uid)
	if err != nil {
		return err
	}
	gone := func() error {
		return fmt.Errorf("player %d's game exited before reaching %s (last %q)", uid, what, p.State())
	}
	after := l.j.Last()
	if want(p.State()) {
		return nil
	}
	if p.Gone() {
		return gone()
	}
	for {
		rec, err := l.j.WaitFor(ctx, after, func(r journal.Record) bool {
			if r.UID != uid {
				return false
			}
			if r.Kind == journal.GpgIn && r.Command == "GameState" && len(r.Args) > 0 {
				s, _ := r.Args[0].(string)
				return want(s)
			}
			return r.Kind == journal.ProcExit || r.Kind == journal.GpgClose
		})
		if err != nil {
			return fmt.Errorf("player %d never reached %s (last %q): %w", uid, what, p.State(), err)
		}
		if rec.Kind == journal.GpgIn {
			return nil
		}
		if p.Gone() { // liveness is updated before the record is journaled
			return gone()
		}
		after = rec.Seq // an adapter exit or a replaced link; keep waiting
	}
}

// addr is where viewer's game must send to reach target's game.
func (l *Launcher) addr(viewer, target *Player) (string, error) {
	switch l.cfg.Mode {
	case ModeDirect:
		target.mu.Lock()
		host := target.host
		target.mu.Unlock()
		return net.JoinHostPort(host, strconv.Itoa(target.seat.LobbyPort())), nil
	case ModeRelay:
		if l.hub != nil {
			return l.hubRelayAddr(viewer.Cfg.UID, target.Cfg.UID)
		}
		loop := net.IPv4(127, 0, 0, 1)
		if _, err := l.relay.Ensure(viewer.Cfg.UID, target.Cfg.UID,
			&net.UDPAddr{IP: loop, Port: viewer.seat.LobbyPort()},
			&net.UDPAddr{IP: loop, Port: target.seat.LobbyPort()}); err != nil {
			return "", err
		}
		return l.relay.AddrFor(viewer.Cfg.UID, target.Cfg.UID)
	default:
		// The ICE adapter replaces this with its local port for the peer.
		return "127.0.0.1:0", nil
	}
}

// HostGame makes uid the host once its game is in the lobby.
func (l *Launcher) HostGame(ctx context.Context, uid int) error {
	p, err := l.Player(uid)
	if err != nil {
		return err
	}
	if err = l.WaitState(ctx, uid, "Lobby"); err != nil {
		return err
	}
	l.mu.Lock()
	l.hostUID = uid
	l.mu.Unlock()
	if err = l.send(p, gpgnet.New("HostGame", l.cfg.Map)); err != nil {
		return err
	}
	p.mu.Lock()
	p.joined = true
	p.mu.Unlock()
	return nil
}

// JoinGame connects uid to the host and to every player already in, in the
// order the FAF lobby server uses.
func (l *Launcher) JoinGame(ctx context.Context, uid int) error {
	host := l.Host()
	if host == 0 {
		return errors.New("join before anyone hosts")
	}
	if host == uid {
		return errors.New("the host cannot join its own game")
	}
	p, err := l.Player(uid)
	if err != nil {
		return err
	}
	h := l.players[host]
	if err = l.WaitState(ctx, uid, "Lobby"); err != nil {
		return err
	}

	toHost, err := l.addr(p, h)
	if err != nil {
		return err
	}
	fromHost, err := l.addr(h, p)
	if err != nil {
		return err
	}
	if err = l.send(p, gpgnet.New("JoinGame", toHost, h.Cfg.Name, host)); err != nil {
		return err
	}
	if err = l.send(h, gpgnet.New("ConnectToPeer", fromHost, p.Cfg.Name, uid)); err != nil {
		return err
	}
	for _, other := range l.order {
		q := l.players[other]
		if other == uid || other == host {
			continue
		}
		q.mu.Lock()
		joined := q.joined
		q.mu.Unlock()
		if !joined {
			continue
		}
		pq, err := l.addr(p, q)
		if err != nil {
			return err
		}
		qp, err := l.addr(q, p)
		if err != nil {
			return err
		}
		if err = l.send(p, gpgnet.New("ConnectToPeer", pq, q.Cfg.Name, other)); err != nil {
			return err
		}
		if err = l.send(q, gpgnet.New("ConnectToPeer", qp, p.Cfg.Name, uid)); err != nil {
			return err
		}
	}
	p.mu.Lock()
	p.joined = true
	p.mu.Unlock()
	return nil
}

// Kill terminates a player's game and adapter, as a crash would.
func (l *Launcher) Kill(uid int) error {
	p, err := l.Player(uid)
	if err != nil {
		return err
	}
	if p.seat != nil {
		p.seat.Kill()
	}
	return nil
}

// PlayerSnapshot is one row of Snapshot.
type PlayerSnapshot struct {
	UID    int    `json:"uid"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Joined bool   `json:"joined"`
	Live   bool   `json:"live"`
	seat.Snapshot
}

// Snapshot is the live state of every player.
func (l *Launcher) Snapshot() map[string]any {
	var rows []PlayerSnapshot
	for _, uid := range l.order {
		p := l.players[uid]
		p.mu.Lock()
		row := PlayerSnapshot{UID: uid, Name: p.Cfg.Name, State: p.state, Joined: p.joined, Live: p.live}
		p.mu.Unlock()
		if p.seat != nil {
			row.Snapshot = p.seat.Snapshot()
		}
		rows = append(rows, row)
	}
	out := map[string]any{"mode": l.cfg.Mode, "host": l.Host(), "players": rows}
	if l.hub != nil {
		out["hub"], out["run"] = l.cfg.Hub, l.cfg.RunID
	}
	if links := l.LinkStats(); links != nil {
		out["links"] = links
	}
	return out
}

// Close kills everything the run started and stops its services.
func (l *Launcher) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	l.mu.Unlock()
	for _, uid := range l.order {
		if s := l.players[uid].seat; s != nil {
			s.Close()
		}
	}
	l.closeHub()
	l.closeServices()
	l.job.Close()
}

func (l *Launcher) closeServices() {
	if l.relay != nil {
		l.relay.Close()
	}
	if l.ice != nil {
		l.ice.Close()
	}
	if l.turn != nil {
		_ = l.turn.Close()
	}
}
