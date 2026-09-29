// Package seat runs one player's game on the machine it is on: the GPGNet
// endpoint the game (or its ICE adapter) connects to, the game's UDP lobby
// port, the adapter and game processes, and the FAF client's part of the
// protocol (CreateLobby once the game reports Idle). Everything it does is
// reported as journal records through a sink, so the same seat serves a
// director in the same process or one on another machine (via an agent).
package seat

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"faf-main/tools/gpgnet"
	"faf-main/tools/icebreaker"
	"faf-main/tools/journal"
	"faf-main/tools/procs"
)

// PrefsShared as Config.Prefs makes the game use the user's Game.prefs itself.
const PrefsShared = "shared"

// Window is a game window's client size.
type Window struct {
	Width  int `yaml:"width" json:"width"`
	Height int `yaml:"height" json:"height"`
}

// ICE puts the game behind a faf-pioneer ICE adapter.
type ICE struct {
	Adapter    string `json:"adapter"`
	APIRoot    string `json:"apiRoot"`
	GameID     uint64 `json:"gameId"`
	Secret     string `json:"-"` // signs the adapter's access token; never sent over the wire
	ForceRelay bool   `json:"forceRelay"`
	LogLevel   int    `json:"logLevel"`
}

// Config describes one seat. It is plain data so it can travel to an agent.
type Config struct {
	UID         int               `json:"uid"`
	Name        string            `json:"name"`
	Team        int               `json:"team"`
	StartSpot   int               `json:"startSpot"`
	Faction     string            `json:"faction,omitempty"`
	Players     int               `json:"players"` // /players N, autolobby only
	AutoLobby   bool              `json:"autoLobby"`
	GameOptions map[string]string `json:"gameOptions,omitempty"`

	Exe      string   `json:"exe"`
	Dir      string   `json:"dir,omitempty"`
	Init     string   `json:"init"`
	Args     []string `json:"args,omitempty"`
	Window   Window   `json:"window"`
	NoSound  bool     `json:"nosound"`
	Position []int    `json:"position,omitempty"` // /position x y
	Prefs    string   `json:"prefs"`              // template path, or PrefsShared
	Spawn    bool     `json:"spawn"`
	RunDir   string   `json:"runDir"`
	// SaveReplay records this instance's replay as <RunDir>/replay-<uid>.
	SaveReplay bool `json:"saveReplay,omitempty"`
	// PrivateCache gives the instance its own shader cache, <RunDir>/cache-<uid>
	// (/cachedir, recovered engine only), so instances can load in parallel.
	PrivateCache bool `json:"privateCache,omitempty"`

	ICE *ICE `json:"ice,omitempty"`
}

// CheckNoFullscreen refuses a fullscreen request anywhere on a command line.
// A fullscreen instance seizes the whole desktop; no seat ever starts one.
func CheckNoFullscreen(where string, args []string) error {
	for _, a := range args {
		if strings.EqualFold(a, "/fullscreen") {
			return fmt.Errorf("%s: %q is refused: only windowed instances are launched", where, a)
		}
	}
	return nil
}

// PrefsDir is the folder the engine resolves /prefs names in
// (USER_LoadPreferences; the default name is Game.prefs).
func PrefsDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
	}
	return filepath.Join(base, "Gas Powered Games", "Supreme Commander Forged Alliance")
}

// PrefsName is the private preferences file of a seat (a name, not a path).
func PrefsName(uid int) string { return fmt.Sprintf("mpemu-p%d.prefs", uid) }

// Snapshot is a seat's live state.
type Snapshot struct {
	GpgPort   int  `json:"gpgnetPort"`
	Connected bool `json:"gpgnetConnected"`
	LobbyPort int  `json:"lobbyPort,omitempty"`
	GamePid   int  `json:"gamePid,omitempty"`
	AdapterID int  `json:"adapterPid,omitempty"`
	External  bool `json:"external,omitempty"`
}

// Seat is one running player.
type Seat struct {
	cfg  Config
	job  *procs.Job
	sink func(journal.Record)

	endpoint    *gpgnet.Endpoint
	lobbyPort   int
	adapterPort int

	mu       sync.Mutex
	external bool
	game     *procs.Process
	adapter  *procs.Process
	adapterC chan struct{}
	once     sync.Once
}

// New validates cfg and opens the seat's GPGNet endpoint and lobby port.
func New(cfg Config, job *procs.Job, sink func(journal.Record)) (*Seat, error) {
	if err := CheckNoFullscreen(fmt.Sprintf("player %d", cfg.UID), cfg.Args); err != nil {
		return nil, err
	}
	if cfg.Window.Width <= 0 || cfg.Window.Height <= 0 {
		return nil, fmt.Errorf("player %d: a window size is required", cfg.UID)
	}
	if cfg.RunDir != "" {
		if err := os.MkdirAll(cfg.RunDir, 0o755); err != nil {
			return nil, err
		}
	}
	s := &Seat{cfg: cfg, job: job, sink: sink, adapterC: make(chan struct{})}
	uid := cfg.UID
	ep, err := gpgnet.Listen("127.0.0.1:0", gpgnet.Handler{
		Connected: func(remote string) {
			if cfg.ICE != nil {
				s.once.Do(func() { close(s.adapterC) })
			}
			s.emit(journal.Record{Kind: journal.GpgConnect, UID: uid, Text: remote})
		},
		Message: s.onMessage,
		Disconnected: func(err error) {
			text := "closed"
			if err != nil {
				text = err.Error()
			}
			s.emit(journal.Record{Kind: journal.GpgClose, UID: uid, Text: text})
		},
	})
	if err != nil {
		return nil, err
	}
	s.endpoint = ep
	if cfg.ICE == nil {
		if s.lobbyPort, err = freeUDPPort(); err != nil {
			ep.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Seat) emit(r journal.Record) { s.sink(r) }

// LobbyPort is the game's UDP lobby port (0 behind an ICE adapter).
func (s *Seat) LobbyPort() int { return s.lobbyPort }

func freeUDPPort() (int, error) {
	// Probe on every interface: in a multi-machine run the game is reached on
	// this machine's LAN address, not only on loopback.
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port, nil
}

func freeTCPPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// Start brings the seat up: the ICE adapter when configured, then the game
// (or printed instructions to start it by hand).
func (s *Seat) Start(ctx context.Context) error {
	gpgPort := s.endpoint.Port()
	if s.cfg.ICE != nil {
		if err := s.startAdapter(ctx); err != nil {
			return err
		}
		gpgPort = s.adapterPort
	}
	return s.startGame(gpgPort)
}

func (s *Seat) startAdapter(ctx context.Context) error {
	var err error
	if s.adapterPort, err = freeTCPPort(); err != nil {
		return err
	}
	ice, uid := s.cfg.ICE, s.cfg.UID
	logDir := filepath.Join(s.cfg.RunDir, fmt.Sprintf("adapter-%d", uid))
	_ = os.MkdirAll(logDir, 0o755)
	args := []string{
		"--user-id", strconv.Itoa(uid),
		"--user-name", s.cfg.Name,
		"--game-id", strconv.FormatUint(ice.GameID, 10),
		"--access-token", icebreaker.MintSignedAccessToken(uint(uid), ice.GameID, ice.Secret),
		"--api-root", ice.APIRoot,
		"--gpgnet-port", strconv.Itoa(s.adapterPort),
		"--gpgnet-client-port", strconv.Itoa(s.endpoint.Port()),
		"--log-level", strconv.Itoa(ice.LogLevel),
		"--log-path", logDir,
	}
	if ice.ForceRelay {
		args = append(args, "--force-turn-relay")
	}
	proc, err := procs.Start(procs.Spec{
		Name: fmt.Sprintf("adapter-%d", uid), Exe: ice.Adapter, Dir: logDir, Args: args,
		Output: filepath.Join(logDir, "stdout.log"),
	}, s.job)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.adapter = proc
	s.mu.Unlock()
	shown := append([]string(nil), args...)
	for i := range shown {
		if i > 0 && shown[i-1] == "--access-token" {
			shown[i] = "<token>"
		}
	}
	s.emit(journal.Record{Kind: journal.ProcStart, UID: uid, Text: "adapter",
		Data: map[string]any{"pid": proc.Pid(), "cmd": procs.CommandLine(ice.Adapter, shown)}})
	go s.watchExit(proc, "adapter")

	select {
	case <-s.adapterC:
		return nil
	case <-proc.Done():
		return fmt.Errorf("player %d: ICE adapter exited (code %d) before connecting; see %s",
			uid, proc.ExitCode(), logDir)
	case <-time.After(30 * time.Second):
		return fmt.Errorf("player %d: ICE adapter did not connect within 30s; see %s", uid, logDir)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GameArgs is the command line a seat's game gets, for a GPGNet endpoint
// (the seat's own, or its ICE adapter's) on gpgPort.
func (c Config) GameArgs(gpgPort int) []string {
	args := []string{
		"/init", c.Init,
		"/nobugreport",
		"/gpgnet", fmt.Sprintf("127.0.0.1:%d", gpgPort),
		"/log", filepath.Join(c.RunDir, fmt.Sprintf("game-%d.log", c.UID)),
		// Always windowed: display preferences alone are not trusted to keep
		// an instance off the whole screen.
		"/windowed", strconv.Itoa(c.Window.Width), strconv.Itoa(c.Window.Height),
	}
	if c.AutoLobby {
		args = append(args,
			"/players", strconv.Itoa(c.Players),
			"/team", strconv.Itoa(c.Team),
			"/startspot", strconv.Itoa(c.StartSpot),
		)
	}
	if c.Faction != "" {
		args = append(args, "/"+c.Faction)
	}
	if len(c.GameOptions) > 0 {
		keys := make([]string, 0, len(c.GameOptions))
		for k := range c.GameOptions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		args = append(args, "/gameoptions")
		for _, k := range keys {
			args = append(args, k+":"+c.GameOptions[k])
		}
	}
	if c.NoSound {
		args = append(args, "/nosound")
	}
	if c.Prefs != PrefsShared {
		args = append(args, "/prefs", PrefsName(c.UID)) // a name inside PrefsDir(), not a path
	}
	if len(c.Position) == 2 {
		args = append(args, "/position", strconv.Itoa(c.Position[0]), strconv.Itoa(c.Position[1]))
	}
	if c.SaveReplay {
		// A path, so every instance records its own: instances sharing a
		// profile otherwise all target LastGame and only the first gets it.
		// The engine appends the replay extension (VCR_CreateReplay).
		args = append(args, "/savereplay", filepath.Join(c.RunDir, fmt.Sprintf("replay-%d", c.UID)))
	}
	if c.PrivateCache {
		args = append(args, "/cachedir", filepath.Join(c.RunDir, fmt.Sprintf("cache-%d", c.UID)))
	}
	return append(args, c.Args...)
}

func (s *Seat) startGame(gpgPort int) error {
	c, uid := s.cfg, s.cfg.UID
	dir := c.Dir
	if dir == "" {
		dir = filepath.Dir(c.Exe)
	}
	if c.Prefs != PrefsShared {
		if err := copyFile(c.Prefs, filepath.Join(PrefsDir(), PrefsName(uid))); err != nil {
			// The instance then starts from empty preferences; /windowed still
			// keeps it off the full screen.
			s.emit(journal.Record{Kind: journal.Warn, UID: uid, Text: "prefs template not copied: " + err.Error()})
		}
	}
	args := c.GameArgs(gpgPort)
	cmdline := procs.CommandLine(c.Exe, args)

	// Always leave a way to start the same instance by hand.
	script := fmt.Sprintf("@echo off\r`ncd /d \"%s\"\r`n%s\r`n", dir, cmdline)
	_ = os.WriteFile(filepath.Join(c.RunDir, fmt.Sprintf("start-game-%d.cmd", uid)), []byte(script), 0o644)
	_ = os.WriteFile(filepath.Join(c.RunDir, fmt.Sprintf("debug-args-%d.txt", uid)),
		[]byte(procs.Arguments(args)+"\r`n"), 0o644)

	if !c.Spawn {
		s.mu.Lock()
		s.external = true
		s.mu.Unlock()
		s.emit(journal.Record{Kind: journal.ProcExternal, UID: uid, Text: "waiting for a game started by hand",
			Data: map[string]any{"exe": c.Exe, "dir": dir, "args": procs.Arguments(args)}})
		fmt.Printf("`n== player %d (%s): start the game yourself ==`n   working dir : %s`n   command     : %s`n   VS args     : %s`n`n",
			uid, c.Name, dir, cmdline, procs.Arguments(args))
		return nil
	}

	proc, err := procs.Start(procs.Spec{Name: fmt.Sprintf("game-%d", uid), Exe: c.Exe, Dir: dir, Args: args}, s.job)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.game = proc
	s.mu.Unlock()
	s.emit(journal.Record{Kind: journal.ProcStart, UID: uid, Text: "game",
		Data: map[string]any{"pid": proc.Pid(), "cmd": cmdline, "dir": dir}})
	go s.watchExit(proc, "game")
	return nil
}

func (s *Seat) watchExit(proc *procs.Process, what string) {
	<-proc.Done()
	s.emit(journal.Record{Kind: journal.ProcExit, UID: s.cfg.UID, Text: what,
		Data: map[string]any{"code": proc.ExitCode(), "killedByMpemu": proc.Killed()}})
}

// onMessage handles one message from the game, acting as the FAF client does.
func (s *Seat) onMessage(m gpgnet.Message) {
	uid := s.cfg.UID
	s.emit(journal.Record{Kind: journal.GpgIn, UID: uid, Command: m.Command, Args: m.Args})
	if m.Command == "GameState" && m.Str(0) == "Idle" {
		mode := 0
		if s.cfg.AutoLobby {
			mode = 1
		}
		// An ICE adapter rewrites the port to its own game-facing UDP port.
		_ = s.Send(gpgnet.New("CreateLobby", mode, s.lobbyPort, s.cfg.Name, uid, 1))
	}
}

// Send delivers one GPGNet message to the game and records it. A host name
// in a JoinGame / ConnectToPeer address is resolved here, on the machine the
// game runs on, so a hub known by name resolves the way this machine sees it
// (split-horizon DNS) and no address is fixed anywhere else.
func (s *Seat) Send(m gpgnet.Message) error {
	if (m.Command == "JoinGame" || m.Command == "ConnectToPeer") && len(m.Args) > 0 {
		if addr, ok := m.Args[0].(string); ok {
			resolved, err := resolveHostPort(addr)
			if err != nil {
				s.emit(journal.Record{Kind: journal.Warn, UID: s.cfg.UID, Text: "resolve " + addr + ": " + err.Error()})
			} else if resolved != addr {
				args := append([]any{resolved}, m.Args[1:]...)
				m = gpgnet.Message{Command: m.Command, Args: args}
			}
		}
	}
	err := s.endpoint.Send(m)
	rec := journal.Record{Kind: journal.GpgOut, UID: s.cfg.UID, Command: m.Command, Args: m.Args}
	if err != nil {
		rec.Text = "send failed: " + err.Error()
	}
	s.emit(rec)
	return err
}

// Kill terminates the game and adapter, as a crash would.
func (s *Seat) Kill() {
	s.mu.Lock()
	game, adapter := s.game, s.adapter
	s.mu.Unlock()
	if game != nil {
		game.Kill()
	}
	if adapter != nil {
		adapter.Kill()
	}
}

// Close kills the seat's processes, closes its endpoint and moves its private
// preferences file into the run directory.
func (s *Seat) Close() {
	s.Kill()
	s.endpoint.Close()
	if s.cfg.Prefs == PrefsShared {
		return
	}
	for _, suffix := range []string{"", ".new"} {
		src := filepath.Join(PrefsDir(), PrefsName(s.cfg.UID)+suffix)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(s.cfg.RunDir, fmt.Sprintf("game-%d.prefs%s", s.cfg.UID, suffix))
		if err := os.Rename(src, dst); err != nil && copyFile(src, dst) == nil {
			_ = os.Remove(src)
		}
	}
}

// Snapshot reports the seat's live state.
func (s *Seat) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{GpgPort: s.endpoint.Port(), Connected: s.endpoint.Connected(),
		LobbyPort: s.lobbyPort, External: s.external}
	if s.game != nil && !s.game.Exited() {
		snap.GamePid = s.game.Pid()
	}
	if s.adapter != nil && !s.adapter.Exited() {
		snap.AdapterID = s.adapter.Pid()
	}
	return snap
}

// resolveHostPort turns "name:port" into "ipv4:port"; addresses pass through.
func resolveHostPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) != nil {
		return addr, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return addr, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), port), nil
		}
	}
	return addr, fmt.Errorf("%s has no IPv4 address", host)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
