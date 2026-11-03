// Package fafclient emulates the FAF client's side of the ICE adapter
// contract (docs/LAUNCHER_ADAPTER_CONTRACT.md) and the lobby server's part in
// pairing players, so any adapter (FAF's faf-ice-adapter.jar, our
// faf-netbridge, the launch shim) can be run unchanged, N players on one
// machine, without the real client or lobby server.
//
// Per player it does what downlords-faf-client's IceAdapterImpl does: pick two
// free TCP ports, start the adapter with the launcher's command line, connect
// JSON-RPC to the RPC port (50 attempts, 250 ms apart), send setLobbyInitMode
// and setIceServers, then start the game with /gpgnet 127.0.0.1:<gpgnet port>.
// Messages from the game (onGpgNetMessageReceived) drive the lobby server's
// part: HostGame for the host, JoinGame/ConnectToPeer with the offer flags of
// FAForever/server gameconnection.py, and IceMsg relayed between adapters.
package fafclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"faf-main/tools/journal"
	"faf-main/tools/procs"
)

// Journal kinds of this package, next to journal's own.
const (
	RPCIn    = "rpc.in"  // adapter -> client
	RPCOut   = "rpc.out" // client -> adapter
	RPCWarn  = "rpc.warn"
	LobbyMsg = "lobby"
)

const (
	connectAttempts = 50
	connectDelay    = 250 * time.Millisecond
)

// Player is one seat.
type Player struct {
	ID    int
	Login string
}

// Adapter describes how to start an adapter for one player.
type Adapter struct {
	// Java is the java executable. Empty runs Exe directly with the adapter
	// arguments (a native adapter tested without the shim).
	Java string
	// NativeDir is the working directory and holds faf-ice-adapter.jar, as
	// the client's -DnativeDir does.
	NativeDir string
	// JavaFXClassPath is appended to the class path after the jar, as the
	// client appends its own javafx-* jars. May be empty.
	JavaFXClassPath string
	// AllowIPv6 leaves out -Dorg.ice4j.ipv6.DISABLED=true.
	AllowIPv6 bool
	// Exe is the native adapter when Java is empty.
	Exe string
	// ForceRelay adds --force-relay.
	ForceRelay bool
	// LogDir is passed in LOG_DIR; per player a subfolder.
	LogDir string
	// Extra arguments appended after the launcher's (tests only).
	Extra []string
}

// Command builds the launcher's command line (IceAdapterImpl.buildCommand).
func (a Adapter) Command(p Player, gameID, rpcPort, gpgPort int, token, icebreakerURL string) []string {
	var cmd []string
	if a.Java != "" {
		cmd = append(cmd, a.Java, "-XX:+UseZGC", "-Xms128m", "-Xmx512m")
		if !a.AllowIPv6 {
			cmd = append(cmd, "-Dorg.ice4j.ipv6.DISABLED=true")
		}
		cp := filepath.Join(a.NativeDir, "faf-ice-adapter.jar")
		if a.JavaFXClassPath != "" {
			cp += string(os.PathListSeparator) + a.JavaFXClassPath
		}
		cmd = append(cmd, "-cp", cp, "com.faforever.iceadapter.IceAdapter")
	} else {
		cmd = append(cmd, a.Exe)
	}
	cmd = append(cmd,
		"--id", strconv.Itoa(p.ID),
		"--game-id", strconv.Itoa(gameID),
		"--login", p.Login,
		"--rpc-port", strconv.Itoa(rpcPort), "--gpgnet-port", strconv.Itoa(gpgPort),
		"--access-token", token,
		"--icebreaker-base-url", icebreakerURL)
	if a.ForceRelay {
		cmd = append(cmd, "--force-relay")
	}
	return append(cmd, a.Extra...)
}

// GameStarter starts the game for one player once its adapter is up. gpgAddr
// is the /gpgnet argument.
type GameStarter func(ctx context.Context, p Player, gpgAddr string) error

// Options for one emulated game.
type Options struct {
	Players    []Player // Players[0] hosts
	GameID     int
	Map        string
	InitMode   string // "normal" or "auto" (matchmaker)
	IceServers []map[string]any
	Adapters   []Adapter // one per player
	StartGame  GameStarter
	Journal    *journal.Journal
	// Job, when set, receives every adapter process so none outlives the run.
	Job *procs.Job
	// Token and IcebreakerURL are passed through; the Java adapter ignores both.
	Token         string
	IcebreakerURL string
}

// Session is one player's client: adapter process plus RPC connection.
type Session struct {
	Player  Player
	RPCPort int
	GpgPort int
	cmd     *exec.Cmd
	conn    net.Conn
	rpc     *Peer
	lobby   *Lobby

	mu        sync.Mutex
	gameState string
	exited    chan struct{}
	exitErr   error
}

// GameState is the last GameState the game reported.
func (s *Session) GameState() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gameState
}

// Exited is closed when the adapter process ends.
func (s *Session) Exited() <-chan struct{} { return s.exited }

// Call sends one API call to this player's adapter and waits for its response.
func (s *Session) Call(ctx context.Context, method string, args ...any) (Message, error) {
	ch, err := s.rpc.Call(method, args...)
	if err != nil {
		return Message{}, err
	}
	select {
	case m := <-ch:
		if m.Error != nil {
			return m, fmt.Errorf("%s: %s", method, m.Error.Message)
		}
		return m, nil
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-s.exited:
		return Message{}, fmt.Errorf("%s: adapter exited", method)
	}
}

// Lobby plays the lobby server's part for one game.
type Lobby struct {
	opts     Options
	j        *journal.Journal
	mu       sync.Mutex
	sessions map[int]*Session
	joinMu   sync.Mutex
	joined   []int // joiners whose join finished, in order (the host is not in it)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Start launches every player's adapter and game. It returns once all RPC
// connections are up; the game proceeds in the background.
func Start(ctx context.Context, opts Options) (*Lobby, error) {
	if len(opts.Players) == 0 || len(opts.Adapters) != len(opts.Players) {
		return nil, errors.New("fafclient: one adapter per player is required")
	}
	if opts.InitMode == "" {
		opts.InitMode = "normal"
	}
	// The client resolves nativeDir with toAbsolutePath, and the adapter runs
	// with it as working directory.
	for i := range opts.Adapters {
		if abs, err := filepath.Abs(opts.Adapters[i].NativeDir); err == nil {
			opts.Adapters[i].NativeDir = abs
		}
	}
	l := &Lobby{opts: opts, j: opts.Journal, sessions: map[int]*Session{}}
	for i, p := range opts.Players {
		s, err := l.startSession(ctx, p, opts.Adapters[i])
		if err != nil {
			l.Close()
			return nil, err
		}
		l.mu.Lock()
		l.sessions[p.ID] = s
		l.mu.Unlock()
	}
	for _, p := range opts.Players {
		s := l.Session(p.ID)
		gpg := "127.0.0.1:" + strconv.Itoa(s.GpgPort)
		if err := opts.StartGame(ctx, p, gpg); err != nil {
			l.Close()
			return nil, fmt.Errorf("fafclient: start game for %s: %w", p.Login, err)
		}
	}
	return l, nil
}

// Session returns a player's session.
func (l *Lobby) Session(id int) *Session {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessions[id]
}

func (l *Lobby) note(uid int, text string, data any) {
	if l.j != nil {
		l.j.Note(LobbyMsg, uid, text, data)
	}
}

func (l *Lobby) startSession(ctx context.Context, p Player, a Adapter) (*Session, error) {
	rpcPort, err := freePort()
	if err != nil {
		return nil, err
	}
	gpgPort, err := freePort()
	if err != nil {
		return nil, err
	}
	s := &Session{Player: p, RPCPort: rpcPort, GpgPort: gpgPort, lobby: l, exited: make(chan struct{})}
	argv := a.Command(p, l.opts.GameID, rpcPort, gpgPort, l.opts.Token, l.opts.IcebreakerURL)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = a.NativeDir
	env := os.Environ()
	if a.LogDir != "" {
		dir := filepath.Join(a.LogDir, p.Login)
		_ = os.MkdirAll(dir, 0o755)
		env = append(env, "LOG_DIR="+dir)
		if f, err := os.Create(filepath.Join(dir, "adapter-stdout.log")); err == nil {
			cmd.Stdout, cmd.Stderr = f, f
		}
	}
	cmd.Env = env
	if l.j != nil {
		l.j.Add(journal.Record{Kind: journal.ProcStart, UID: p.ID, Text: strings.Join(argv, " ")})
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("fafclient: start adapter for %s: %w", p.Login, err)
	}
	s.cmd = cmd
	if l.opts.Job != nil {
		_ = l.opts.Job.Assign(cmd.Process.Pid)
	}
	go func() {
		s.exitErr = cmd.Wait()
		if l.j != nil {
			l.j.Add(journal.Record{Kind: journal.ProcExit, UID: p.ID, Text: fmt.Sprint(s.exitErr)})
		}
		close(s.exited)
	}()

	// IceAdapterImpl.initializeIceAdapterConnection.
	var conn net.Conn
	for attempt := 0; attempt < connectAttempts; attempt++ {
		conn, err = net.DialTimeout("tcp", "localhost:"+strconv.Itoa(rpcPort), time.Second)
		if err == nil {
			break
		}
		select {
		case <-s.exited:
			return nil, fmt.Errorf("fafclient: adapter for %s exited before RPC connected: %v", p.Login, s.exitErr)
		case <-time.After(connectDelay):
		}
	}
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("fafclient: RPC connect for %s: %w", p.Login, err)
	}
	s.conn = conn
	s.rpc = NewPeer(conn, func(dir string, f Frame) {
		if l.j == nil {
			return
		}
		kind := RPCOut
		if dir == "in" {
			kind = RPCIn
		}
		l.j.Add(journal.Record{Kind: kind, UID: p.ID, Text: strings.TrimSpace(f.Text)})
		if f.NonASCII {
			l.j.Add(journal.Record{Kind: RPCWarn, UID: p.ID, Text: "frame has bytes >= 0x80; the Java reader casts each byte to a char"})
		}
	})
	go func() {
		err := s.rpc.Serve(conn, func(m Message) { l.onCallback(s, m) })
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			l.note(p.ID, "rpc read: "+err.Error(), nil)
		}
	}()

	// Right after connecting the client sends setLobbyInitMode; setIceServers
	// follows when the lobby server's game_launch hands out the coturn list.
	if _, err := s.rpc.Call("setLobbyInitMode", l.opts.InitMode); err != nil {
		return nil, err
	}
	if l.opts.IceServers != nil {
		if _, err := s.rpc.Call("setIceServers", l.opts.IceServers); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func str(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

func num(raw json.RawMessage) int {
	var n int
	_ = json.Unmarshal(raw, &n)
	return n
}

// onCallback handles one adapter -> client message (IceAdapterCallbacks).
func (l *Lobby) onCallback(s *Session, m Message) {
	if m.ID != nil { // the adapter never sends requests; answer anyway
		_ = s.rpc.Respond(*m.ID, nil)
	}
	switch m.Method {
	case "onGpgNetMessageReceived":
		if len(m.Params) < 2 {
			return
		}
		cmd := str(m.Params[0])
		var args []json.RawMessage
		_ = json.Unmarshal(m.Params[1], &args)
		if cmd == "GameState" && len(args) > 0 {
			state := str(args[0])
			s.mu.Lock()
			s.gameState = state
			s.mu.Unlock()
			if state == "Lobby" {
				l.onLobby(s)
			}
		}
	case "onIceMsg":
		// onIceMsg(localId, remoteId, message) -> lobby server IceMsg ->
		// receiver's client iceMsg(senderId, message).
		if len(m.Params) < 3 {
			return
		}
		from, to := num(m.Params[0]), num(m.Params[1])
		var msg any
		_ = json.Unmarshal(m.Params[2], &msg)
		if peer := l.Session(to); peer != nil {
			_, _ = peer.rpc.Call("iceMsg", from, msg)
		} else {
			l.note(s.Player.ID, fmt.Sprintf("IceMsg for unknown player %d", to), nil)
		}
	case "onConnectionStateChanged":
		if len(m.Params) > 0 && str(m.Params[0]) == "Disconnected" {
			// The client stops the adapter (IceAdapterImpl.onIceAdapterStateChanged).
			_, _ = s.rpc.Call("quit")
		}
	}
}

// onLobby is FAForever/server GameConnection._handle_lobby_state.
func (l *Lobby) onLobby(s *Session) {
	host := l.opts.Players[0]
	if s.Player.ID == host.ID {
		l.note(s.Player.ID, "HostGame "+l.opts.Map, nil)
		_, _ = s.rpc.Call("hostGame", l.opts.Map)
		return
	}
	// The real server aborts a join while the host is not in the lobby ("The
	// host left the lobby"); here every game starts at once, so the joiner
	// waits for the host instead. Joins run one at a time, as the server
	// handles them, so each joiner is paired with the players whose join
	// finished before its own.
	go func() {
		hs := l.Session(host.ID)
		for hs == nil || hs.GameState() != "Lobby" {
			time.Sleep(50 * time.Millisecond)
			hs = l.Session(host.ID)
		}
		l.joinMu.Lock()
		defer l.joinMu.Unlock()
		l.join(s, hs, append([]int(nil), l.joined...))
		l.joined = append(l.joined, s.Player.ID)
	}()
}

func (l *Lobby) join(s, hs *Session, others []int) {
	host := hs.Player
	// connect_to_host: JoinGame to the joiner, ConnectToPeer(offer) to the host.
	l.note(s.Player.ID, "JoinGame "+host.Login, nil)
	_, _ = s.rpc.Call("joinGame", host.Login, host.ID)
	_, _ = hs.rpc.Call("connectToPeer", s.Player.Login, s.Player.ID, true)
	// connect_to_peer for every other player already in the game: the joiner
	// offers, the other side answers.
	for _, id := range others {
		o := l.Session(id)
		_, _ = s.rpc.Call("connectToPeer", o.Player.Login, o.Player.ID, true)
		_, _ = o.rpc.Call("connectToPeer", s.Player.Login, s.Player.ID, false)
	}
}

// DisconnectPeers has every adapter drop every other player, as the server's
// DisconnectFromPeer does when a player leaves.
func (l *Lobby) DisconnectPeers() {
	for _, a := range l.opts.Players {
		s := l.Session(a.ID)
		if s == nil || s.rpc == nil {
			continue
		}
		for _, b := range l.opts.Players {
			if b.ID != a.ID {
				_, _ = s.rpc.Call("disconnectFromPeer", b.ID)
			}
		}
	}
}

// Close sends quit to every adapter and kills what is still running after 3 s.
func (l *Lobby) Close() {
	l.mu.Lock()
	sessions := make([]*Session, 0, len(l.sessions))
	for _, s := range l.sessions {
		sessions = append(sessions, s)
	}
	l.mu.Unlock()
	for _, s := range sessions {
		if s.rpc != nil {
			_, _ = s.rpc.Call("quit")
		}
	}
	for _, s := range sessions {
		select {
		case <-s.exited:
		case <-time.After(3 * time.Second):
			if s.cmd != nil && s.cmd.Process != nil {
				_ = s.cmd.Process.Kill()
			}
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}
}

// ReadTrace is a helper for tests: the RPC frames of one player, in order.
func ReadTrace(path string, uid int) ([]journal.Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []journal.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var r journal.Record
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.UID == uid && (r.Kind == RPCIn || r.Kind == RPCOut) {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}
