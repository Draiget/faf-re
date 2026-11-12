package launcher

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"faf-main/tools/journal"
	"faf-main/tools/seat"
)

func newTestLauncher(t *testing.T, cfg Config) *Launcher {
	t.Helper()
	cfg.RunDir = t.TempDir()
	j, _ := journal.New("", nil)
	l, err := New(cfg, j)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l
}

// Every instance must be told to run windowed, whatever the prefs say, and
// get its own preferences file by bare name (the engine resolves /prefs
// inside the preferences folder; a path there silently yields empty prefs,
// which is how a run once came up fullscreen).
func TestGameArgsAlwaysWindowed(t *testing.T) {
	l := newTestLauncher(t, Config{Game: GameConfig{Exe: "game.exe", Tile: true},
		Players: []PlayerConfig{{UID: 1}, {UID: 2}}})
	for _, uid := range l.Players() {
		p, _ := l.Player(uid)
		args := l.seatConfig(p).GameArgs(1234)
		line := strings.Join(args, " ")
		for i, a := range args {
			if a == "/prefs" && (i+1 >= len(args) || strings.ContainsAny(args[i+1], `/\:`)) {
				t.Fatalf("player %d /prefs must be a bare file name: %s", uid, line)
			}
		}
		if !strings.Contains(line, "/windowed 1600 1000") {
			t.Fatalf("player %d args lack /windowed: %s", uid, line)
		}
		if strings.Contains(strings.ToLower(line), "/fullscreen") {
			t.Fatalf("player %d args ask for fullscreen: %s", uid, line)
		}
		if !strings.Contains(line, "/prefs "+seat.PrefsName(uid)) {
			t.Fatalf("player %d has no private prefs file: %s", uid, line)
		}
	}
}

func TestFullscreenRefused(t *testing.T) {
	for _, cfg := range []Config{
		{Game: GameConfig{Exe: "game.exe", Args: []string{"/fullscreen", "1920", "1080"}}, Players: []PlayerConfig{{UID: 1}}},
		{Game: GameConfig{Exe: "game.exe"}, Players: []PlayerConfig{{UID: 1, Args: []string{"/FullScreen"}}}},
	} {
		if err := cfg.Normalize(); err == nil || !strings.Contains(err.Error(), "windowed") {
			t.Fatalf("fullscreen config accepted: %+v (err %v)", cfg, err)
		}
	}
	// A seat refuses it on its own too: an agent must not start one for a
	// remote director that skipped validation.
	_, err := seat.New(seat.Config{UID: 1, Args: []string{"/fullscreen"}, Window: seat.Window{Width: 800, Height: 600}}, nil, nil)
	if err == nil {
		t.Fatal("seat accepted /fullscreen")
	}
}

func TestAutolobbyNeedsDistinctStartSpots(t *testing.T) {
	cfg := Config{Game: GameConfig{Exe: "game.exe"},
		Players: []PlayerConfig{{UID: 1, StartSpot: 1}, {UID: 2, StartSpot: 1}}}
	if err := cfg.Normalize(); err == nil {
		t.Fatal("duplicate start spots accepted for lobby auto")
	}
}

func serverConfig() Config {
	return Config{Mode: ModeServer, Game: GameConfig{Exe: "game.exe"},
		Server: ServerConfig{Address: "10.0.0.1:27050"},
		Players: []PlayerConfig{
			{UID: 1001, ServerToken: "token-of-seat-one"},
			{UID: 1002, ServerToken: "token-of-seat-two", ServerDelivery: seat.DeliverArgs},
			{UID: 1003, ServerToken: "token-of-seat-three"},
		}}
}

// Mode server: an address, one valid token per player, each its own, and a known delivery.
func TestServerModeChecksItsSettings(t *testing.T) {
	for name, edit := range map[string]func(*Config){
		"no address":      func(c *Config) { c.Server.Address = "" },
		"missing token":   func(c *Config) { c.Players[1].ServerToken = "" },
		"token w/ space":  func(c *Config) { c.Players[1].ServerToken = "two words" },
		"shared token":    func(c *Config) { c.Players[2].ServerToken = c.Players[0].ServerToken },
		"unknown deliver": func(c *Config) { c.Players[0].ServerDelivery = "mail" },
	} {
		cfg := serverConfig()
		edit(&cfg)
		if err := cfg.Normalize(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	cfg := serverConfig()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.Players[0].ServerDelivery != seat.DeliverGpgNet || cfg.Players[1].ServerDelivery != seat.DeliverArgs {
		t.Fatalf("deliveries %q %q", cfg.Players[0].ServerDelivery, cfg.Players[1].ServerDelivery)
	}
}

// Plan WP2.9: each seat is handed its own connection string and nothing of another player's, whichever way it is
// delivered; the lobby steps are the server's.
func TestServerModeSeatsCarryOnlyTheirOwnToken(t *testing.T) {
	l := newTestLauncher(t, serverConfig())
	tokens := map[int]string{1001: "token-of-seat-one", 1002: "token-of-seat-two", 1003: "token-of-seat-three"}
	for _, uid := range l.Players() {
		p, _ := l.Player(uid)
		sc := l.seatConfig(p)
		raw, err := json.Marshal(sc)
		if err != nil {
			t.Fatal(err)
		}
		line := strings.Join(sc.GameArgs(1234), " ")
		for other, tok := range tokens {
			inConfig, inArgs := strings.Contains(string(raw), tok), strings.Contains(line, tok)
			if other == uid {
				if !inConfig || sc.Server == nil || sc.Server.Token != tok || sc.Server.Address != "10.0.0.1:27050" {
					t.Fatalf("player %d lacks its own connection string: %s", uid, raw)
				}
				if inArgs != (sc.Server.Delivery == seat.DeliverArgs) {
					t.Fatalf("player %d (%s): own token on the command line = %v: %s", uid, sc.Server.Delivery, inArgs, line)
				}
				continue
			}
			if inConfig || inArgs {
				t.Fatalf("player %d was handed player %d's token", uid, other)
			}
		}
		if strings.Contains(line, "/players") {
			t.Fatalf("player %d: the server's signals pick the lobby script, not /players: %s", uid, line)
		}
	}
	if err := l.HostGame(context.Background(), 1001); err == nil {
		t.Fatal("HostGame in mode server")
	}
	if err := l.JoinGame(context.Background(), 1002); err == nil {
		t.Fatal("JoinGame in mode server")
	}
}

// The check a scenario runs at its end (ownServerTokenOnly) finds a token sent to the wrong seat, a token in the
// journal and another player's token in a game's log.
func TestCheckServerTokensFindsLeaks(t *testing.T) {
	l := newTestLauncher(t, serverConfig())
	tag := func(tok string) string { return seat.TokenTag(tok) }
	l.j.Add(journal.Record{Kind: journal.GpgOut, UID: 1001, Command: "JoinServer",
		Args: []any{"10.0.0.1:27050", tag("token-of-seat-one"), int32(1001)}})
	l.j.Add(journal.Record{Kind: journal.GpgOut, UID: 1003, Command: "JoinServer",
		Args: []any{"10.0.0.1:27050", tag("token-of-seat-three"), int32(1003)}})
	_ = os.WriteFile(filepath.Join(l.cfg.RunDir, "debug-args-1002.txt"), []byte("/servertoken token-of-seat-two"), 0o644)
	if res := l.CheckServerTokens(); len(res.Fails) != 0 {
		t.Fatalf("a clean run fails: %v", res.Fails)
	}

	l.j.Add(journal.Record{Kind: journal.GpgOut, UID: 1003, Command: "JoinServer",
		Args: []any{"10.0.0.1:27050", tag("token-of-seat-one"), int32(1003)}})
	l.j.Add(journal.Record{Kind: journal.Note, Text: "token-of-seat-two"})
	_ = os.WriteFile(filepath.Join(l.cfg.RunDir, "game-1001.log"), []byte("x token-of-seat-three y"), 0o644)
	res := l.CheckServerTokens()
	want := []string{"player 1003 was sent player 1001's token", "holds player 1002's token",
		"player 1001's game-1001.log holds player 1003's token", "player 1003's JoinServer doesn't carry its own token"}
	all := strings.Join(res.Fails, "\n")
	for _, w := range want {
		if !strings.Contains(all, w) {
			t.Fatalf("missing %q in:\n%s", w, all)
		}
	}
}
