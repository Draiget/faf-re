package launcher

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"faf-main/tools/relay"
	"faf-main/tools/seat"
)

// Mode selects how game UDP traffic travels between instances.
type Mode string

const (
	// ModeDirect: games talk to each other's lobby ports on 127.0.0.1.
	ModeDirect Mode = "direct"
	// ModeRelay: every pair goes through mpemu's UDP relay, which can add
	// latency, jitter, loss and partitions.
	ModeRelay Mode = "relay"
	// ModeICE: every game sits behind a faf-pioneer ICE adapter; traffic goes
	// over WebRTC data channels, signalled through mpemu's icebreaker and
	// optionally relayed by its TURN server.
	ModeICE Mode = "ice"
	// ModeContract: every game sits behind an adapter of the FAF client's ICE
	// adapter contract (FAF's faf-ice-adapter.jar, faf-netbridge, the launch
	// shim), started and driven as the FAF client does
	// (docs/LAUNCHER_ADAPTER_CONTRACT.md). Local seats only.
	ModeContract Mode = "contract"
)

// LobbyKind selects the lobby Lua the game opens (CreateLobby's init mode).
type LobbyKind string

const (
	// LobbyAuto opens autolobby.lua, which launches by itself once every
	// player (/players N) is connected to every other. Unattended runs use it.
	LobbyAuto LobbyKind = "auto"
	// LobbyNormal opens the regular custom-game lobby (manual launch).
	LobbyNormal LobbyKind = "normal"
)

// LeavePolicy decides when the emulated lobby server tells the remaining
// players that someone left (DisconnectFromPeer).
type LeavePolicy string

const (
	LeaveInLobby LeavePolicy = "lobby" // FAF server behaviour: only before launch
	LeaveAlways  LeavePolicy = "always"
	LeaveNever   LeavePolicy = "never"
)

// GameConfig describes how game instances are started.
type GameConfig struct {
	// Exe is the game executable (ForgedAlliance.exe, or a recovered main.exe).
	Exe string `yaml:"exe"`
	// Dir is the working directory; defaults to the directory of Exe.
	Dir string `yaml:"dir"`
	// Init is the init file; relative paths resolve against the FAF bin folder.
	Init string `yaml:"init"`
	// Args are appended to every instance's command line.
	Args []string `yaml:"args"`
	// Prefs is the preferences template each instance gets its own copy of.
	// Empty uses the user's Game.prefs; "shared" makes every instance use
	// Game.prefs itself (they then all rewrite it on exit). The engine takes
	// /prefs as a file name inside seat.PrefsDir(), never a path, so copies are
	// placed there as mpemu-p<uid>.prefs and moved into the run directory
	// when the run ends.
	Prefs string `yaml:"prefs"`
	// NoSound passes /nosound (several instances fighting over one audio
	// device is a common source of noise in multi-instance runs).
	NoSound bool `yaml:"nosound"`
	// Tile passes /position so the windows cascade instead of stacking exactly
	// on top of each other.
	Tile bool `yaml:"tile"`
	// Window is the client size every instance gets through `/windowed W H`.
	// That flag is always passed: the engine parses it itself (0x008D02D0,
	// aliases "window" and "size") and it overrides the display preferences,
	// so an instance can never come up fullscreen. Default 1600x1000.
	Window seat.Window `yaml:"window"`
	// Spawn starts the game; false prints the command line and waits for the
	// game to be started by hand, e.g. from a debugger.
	Spawn *bool `yaml:"spawn"`
	// SaveReplays makes every instance record its replay into the run
	// directory as replay-<uid>.scfareplay, so the command streams the
	// clients dispatched can be compared afterwards.
	SaveReplays bool `yaml:"saveReplays"`
}

// ICEConfig configures ModeICE.
type ICEConfig struct {
	// Adapter is faf-pioneer's faf-adapter executable.
	Adapter string `yaml:"adapter"`
	// ForceRelay makes every connection use the TURN relay.
	ForceRelay bool `yaml:"forceRelay"`
	// LogLevel is passed to the adapter (-1 trace .. 4 fatal).
	LogLevel int `yaml:"logLevel"`
	// NoTurn hands out no ICE servers at all (host candidates only).
	NoTurn bool `yaml:"noTurn"`
}

// ContractConfig configures ModeContract.
type ContractConfig struct {
	// NativeDir holds faf-ice-adapter.jar (the client's nativeDir); the jar
	// runs from there with Java and the client's JavaFX jars.
	NativeDir string `yaml:"nativeDir"`
	// Java is the java executable (default: the FAF client's bundled one).
	Java string `yaml:"java"`
	// ClientLib is the FAF client's lib folder, for its javafx-* jars.
	ClientLib string `yaml:"clientLib"`
	// Adapter is the default per player: "jar" (NativeDir's jar, the default),
	// the path of a native adapter (faf-netbridge.exe) run directly, or
	// "native": no adapter, the game links every peer itself (issue #274).
	Adapter string `yaml:"adapter"`
	// NativeBind is /nativenetbind for "native" players: the address ICE host
	// candidates use (e.g. 192.168.42.77 where inbound UDP to 0.0.0.0 is dropped).
	NativeBind string `yaml:"nativeBind"`
	// ExeArgs go after the launcher's arguments for native adapters only
	// (e.g. --bind-address 192.168.42.77 where inbound UDP to 0.0.0.0 is dropped).
	ExeArgs []string `yaml:"exeArgs"`
	// ForceRelay passes --force-relay.
	ForceRelay bool `yaml:"forceRelay"`
	// NoTurn hands out no ICE servers.
	NoTurn bool `yaml:"noTurn"`
	// IceServers, when set, are handed out instead of mpemu's own TURN server
	// (use with noTurn), e.g. a TURN server on another machine. Every field
	// expands %VAR% and $VAR, so a scenario names no address itself.
	IceServers []IceServerConfig `yaml:"iceServers"`
	// Shaping is where link steps apply: "turn" (default) in mpemu's TURN
	// server, which shapes only paths through it; "links" in every netlink
	// link's sends (FAF_NETLINK_TEST_SHAPING), whichever path ICE picks. Use
	// "links" when every player is our build, the bridge or the bridge's
	// retail game, never with the Java adapter (issue #242).
	Shaping string `yaml:"shaping"`
}

// IceServerConfig is one entry of ContractConfig.IceServers, in the client's
// setIceServers shape.
type IceServerConfig struct {
	URLs       []string `yaml:"urls"`
	Username   string   `yaml:"username"`
	Credential string   `yaml:"credential"`
}

// PlayerConfig is one seat.
type PlayerConfig struct {
	UID       int      `yaml:"uid"`
	Name      string   `yaml:"name"`
	Team      int      `yaml:"team"`
	StartSpot int      `yaml:"startSpot"`
	Faction   string   `yaml:"faction"` // uef, aeon, cybran, seraphim, random
	Exe       string   `yaml:"exe"`     // overrides GameConfig.Exe for this player
	Args      []string `yaml:"args"`
	Spawn     *bool    `yaml:"spawn"`
	// Adapter overrides ContractConfig.Adapter for this player (ModeContract).
	Adapter string `yaml:"adapter"`
	// Agent runs this player on another machine: the name an `mpemu agent`
	// registered with on the hub. Empty runs it here.
	Agent string `yaml:"agent"`
}

// Config is a whole run.
type Config struct {
	GameID     uint64            `yaml:"gameId"`
	Mode       Mode              `yaml:"mode"`
	Lobby      LobbyKind         `yaml:"lobby"`
	Map        string            `yaml:"map"`
	Leave      LeavePolicy       `yaml:"leave"`
	Game       GameConfig        `yaml:"game"`
	ICE        ICEConfig         `yaml:"ice"`
	Contract   ContractConfig    `yaml:"contract"`
	Link       relay.Impairment  `yaml:"link"`
	Players    []PlayerConfig    `yaml:"players"`
	GameOption map[string]string `yaml:"gameOptions"`
	// Hub is the root URL of an mpemu hub (cmd/mpemu-server) when players run
	// on several machines or through a remote relay, e.g.
	// https://faftest.zontwelg.net. A DNS name only: the MPEMU_HUB
	// environment variable overrides it locally, never an address in a file.
	Hub string `yaml:"hub"`

	// Filled by the runner, not the scenario file.
	HubSecret string `yaml:"-"` // MPEMU_SECRET / -secret-file
	Advertise string `yaml:"-"` // how other machines reach games on this one
	RunID     string `yaml:"-"`
	RunDir    string `yaml:"-"`
	HTTPAddr  string `yaml:"-"`
	TurnPort  int    `yaml:"-"`
	TurnIP    string `yaml:"-"`
	FAFBinDir string `yaml:"-"`
}

// DefaultFAFBin is where the FAF client installs the game data and init files.
func DefaultFAFBin() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "FAForever", "bin")
}

var winEnvVar = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_()]*)%`)

// ExpandPath expands %VAR% (Windows) and $VAR / ${VAR} references.
func ExpandPath(s string) string {
	if s == "" {
		return s
	}
	s = winEnvVar.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := os.LookupEnv(m[1 : len(m)-1]); ok {
			return v
		}
		return m
	})
	return os.ExpandEnv(s)
}

// Normalize fills defaults and validates.
func (c *Config) Normalize() error {
	c.Game.Exe = ExpandPath(c.Game.Exe)
	c.Game.Dir = ExpandPath(c.Game.Dir)
	c.Game.Init = ExpandPath(c.Game.Init)
	c.Game.Prefs = ExpandPath(c.Game.Prefs)
	c.ICE.Adapter = ExpandPath(c.ICE.Adapter)
	c.Contract.NativeDir = ExpandPath(c.Contract.NativeDir)
	c.Contract.Java = ExpandPath(c.Contract.Java)
	c.Contract.ClientLib = ExpandPath(c.Contract.ClientLib)
	c.Contract.Adapter = ExpandPath(c.Contract.Adapter)
	for i := range c.Contract.ExeArgs {
		c.Contract.ExeArgs[i] = ExpandPath(c.Contract.ExeArgs[i])
	}
	if c.Contract.Java == "" {
		c.Contract.Java = `C:\Program Files\FAF Client\jre\bin\java.exe`
	}
	if c.Contract.ClientLib == "" {
		c.Contract.ClientLib = `C:\Program Files\FAF Client\lib`
	}
	for i := range c.Players {
		c.Players[i].Exe = ExpandPath(c.Players[i].Exe)
		c.Players[i].Adapter = ExpandPath(c.Players[i].Adapter)
	}
	if c.GameID == 0 {
		c.GameID = 100
	}
	if c.Mode == "" {
		c.Mode = ModeDirect
	}
	switch c.Mode {
	case ModeDirect, ModeRelay, ModeICE, ModeContract:
	default:
		return fmt.Errorf("mode %q: want direct, relay, ice or contract", c.Mode)
	}
	if c.Lobby == "" {
		c.Lobby = LobbyAuto
	}
	if c.Leave == "" {
		c.Leave = LeaveInLobby
	}
	if c.Map == "" {
		c.Map = "SCMP_009"
	}
	if c.FAFBinDir == "" {
		c.FAFBinDir = DefaultFAFBin()
	}
	if c.Game.Exe == "" {
		c.Game.Exe = filepath.Join(c.FAFBinDir, "ForgedAlliance.exe")
	}
	if c.Game.Init == "" {
		c.Game.Init = "init.lua"
	}
	if !filepath.IsAbs(c.Game.Init) {
		c.Game.Init = filepath.Join(c.FAFBinDir, c.Game.Init)
	}
	if c.Game.Prefs == "" {
		c.Game.Prefs = filepath.Join(seat.PrefsDir(), "Game.prefs")
	}
	if c.Game.Window.Width <= 0 || c.Game.Window.Height <= 0 {
		// Big enough for the operator's ui_scale 1.25 (1024x768 renders the
		// UI too large at that scale).
		c.Game.Window = seat.Window{Width: 1600, Height: 1000}
	}
	if err := seat.CheckNoFullscreen("game.args", c.Game.Args); err != nil {
		return err
	}
	for _, p := range c.Players {
		if err := seat.CheckNoFullscreen(fmt.Sprintf("player %d args", p.UID), p.Args); err != nil {
			return err
		}
	}
	for _, p := range c.Players {
		if p.Agent != "" && c.Hub == "" {
			return fmt.Errorf("player %d runs on agent %q, which needs a hub (hub: / MPEMU_HUB)", p.UID, p.Agent)
		}
	}
	if c.Mode == ModeICE && c.ICE.Adapter == "" && !c.allRemote() {
		return fmt.Errorf("mode ice needs ice.adapter (faf-pioneer's faf-adapter.exe)")
	}
	if len(c.Players) < 1 {
		return fmt.Errorf("no players")
	}
	seen := map[int]bool{}
	for i := range c.Players {
		p := &c.Players[i]
		if p.UID == 0 {
			p.UID = i + 1
		}
		if seen[p.UID] {
			return fmt.Errorf("duplicate player uid %d", p.UID)
		}
		seen[p.UID] = true
		if p.Name == "" {
			p.Name = fmt.Sprintf("Player%d", p.UID)
		}
		if p.StartSpot == 0 {
			p.StartSpot = i + 1
		}
		if p.Team == 0 {
			p.Team = i + 2 // FAF teams: 1 is "no team"; one team each is FFA
		}
	}
	if c.Lobby == LobbyAuto {
		// autolobby indexes its connection matrix by start spot, 1..N.
		spots := map[int]bool{}
		for _, p := range c.Players {
			if p.StartSpot < 1 || p.StartSpot > len(c.Players) || spots[p.StartSpot] {
				return fmt.Errorf("lobby auto: player %d start spot %d must be unique within 1..%d",
					p.UID, p.StartSpot, len(c.Players))
			}
			spots[p.StartSpot] = true
		}
	}
	return nil
}

// allRemote reports whether every player runs on an agent (the director
// then needs no adapter of its own).
func (c *Config) allRemote() bool {
	for _, p := range c.Players {
		if p.Agent == "" {
			return false
		}
	}
	return len(c.Players) > 0
}

// anyRemote reports whether some player runs on another machine.
func (c *Config) anyRemote() bool {
	for _, p := range c.Players {
		if p.Agent != "" {
			return true
		}
	}
	return false
}

func boolOr(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}
