package launcher

import (
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
