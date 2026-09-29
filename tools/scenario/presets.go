package scenario

import (
	"fmt"
	"time"

	"faf-main/tools/journal"
	"faf-main/tools/launcher"
	"faf-main/tools/relay"
	"faf-main/tools/seat"
)

func players(n int) []launcher.PlayerConfig {
	out := make([]launcher.PlayerConfig, n)
	for i := range out {
		out[i] = launcher.PlayerConfig{UID: i + 1}
	}
	return out
}

// Lobby is the "mpemu lobby" preset: start everyone, host on player 1, join
// the rest, then hand over to the console.
func Lobby(cfg launcher.Config, n int) *Scenario {
	if len(cfg.Players) == 0 {
		cfg.Players = players(n)
	}
	return &Scenario{
		Name:    fmt.Sprintf("lobby-%dp-%s", len(cfg.Players), cfg.Mode),
		Timeout: 24 * time.Hour,
		Config:  cfg,
		Steps: []Step{
			{Start: &UIDs{All: true}},
			{Host: cfg.Players[0].UID},
			{Join: &UIDs{Others: true}},
			{Interactive: true},
		},
		Expect: Expect{NoDesync: true},
	}
}

// HubSelftests exercise the multi-machine path from one machine: two agent
// processes (named by agents) stand in for two test PCs, and players are
// spread over them and the director. Everything a real multi-machine run
// does crosses the hub: seat commands, records, relay links and impairment,
// and ICE signalling plus TURN.
//
// remote says the hub is a real remote host rather than a local process.
// Relayed paths then carry the internet round trip twice (game -> hub ->
// game), so their latency bounds go and their loss bound loosens; what must
// still hold is that everyone connects, impairment and isolation reach the
// hub's relay, and ICE runs through TURN only.
func HubSelftests(fakegameExe, adapter string, agents [2]string, remote bool) []*Scenario {
	a, b := agents[0], agents[1]
	base := func(name string, mode launcher.Mode, where ...string) *Scenario {
		players := make([]launcher.PlayerConfig, len(where))
		for i, w := range where {
			players[i] = launcher.PlayerConfig{UID: i + 1, Agent: w}
		}
		return &Scenario{
			Name:    name,
			Timeout: 3 * time.Minute,
			Config: launcher.Config{
				Mode:    mode,
				Lobby:   launcher.LobbyAuto,
				Hub:     "set-by-selftest",
				Game:    launcher.GameConfig{Exe: fakegameExe, Prefs: seat.PrefsShared},
				ICE:     launcher.ICEConfig{Adapter: adapter},
				Players: players,
			},
			Steps: []Step{
				{Start: &UIDs{All: true}},
				{Host: 1},
				{Join: &UIDs{Others: true}},
				{WaitState: &WaitState{UIDs: UIDs{All: true}, State: "Launching", Timeout: time.Minute}},
				{Wait: 5 * time.Second},
			},
		}
	}
	noLoss := 0.0

	// Direct games talk over this machine's loopback whatever the hub is.
	direct := base("selftest-hub-direct", launcher.ModeDirect, a, b)
	direct.Expect = Expect{AllLaunched: true, NoCrash: true,
		PeerStats: &PeerStatsExpect{MinAnswered: 20, MaxAvgRTT: 20 * time.Millisecond, MaxLoss: &noLoss}}

	relayed := base("selftest-hub-relay", launcher.ModeRelay, a, b, "")
	relayed.Link = relay.Impairment{} // latched hub relay, impaired mid-run below
	relayed.Steps = append(relayed.Steps,
		Step{Link: &LinkStep{From: 1, To: 2, Impairment: relay.Impairment{Latency: 30 * time.Millisecond}}},
		Step{Wait: 8 * time.Second},
		Step{Isolate: 3},
		Step{Wait: 3 * time.Second},
		Step{Restore: 3},
		Step{Wait: 3 * time.Second},
	)
	relayed.Expect = Expect{AllLaunched: true, NoCrash: true,
		Present:   []Match{{Kind: journal.RelayLink, Arg: "impairment"}, {Kind: journal.RelayLink, Arg: "isolate"}},
		PeerStats: &PeerStatsExpect{MinAnswered: 20}}

	out := []*Scenario{direct, relayed}
	if adapter != "" {
		ice := base("selftest-hub-ice-turn", launcher.ModeICE, a, b)
		ice.ICE.ForceRelay = true
		iceLoss, iceRTT := 0.02, 50*time.Millisecond
		if remote {
			iceLoss, iceRTT = 0.05, 0
			// Load like the game does. faf-pioneer restarts a peer whose first
			// offer is still unanswered when ConnectToPeer arrives, without
			// telling the other side (peer_manager.go addPeerIfMissing), and
			// the two never agree again. Through a remote TURN the offer takes
			// long enough that an instantly loaded fakegame always hits it.
			ice.Game.Args = []string{"/loadtime", "4s"}
		}
		ice.Expect = Expect{AllLaunched: true, NoCrash: true, MinTurnAllocations: 2, RelayOnly: true,
			PeerStats: &PeerStatsExpect{MinAnswered: 20, MaxAvgRTT: iceRTT, MaxLoss: &iceLoss}}
		out = append(out, ice)
	}
	return out
}

// Selftests are the stack checks run against fakegame instead of the game:
// every mode must connect everyone, and relay impairment must be visible in
// what the games measure. adapter is only needed for the ICE cases.
func Selftests(fakegameExe, adapter string) []*Scenario {
	base := func(name string, mode launcher.Mode, n int) *Scenario {
		return &Scenario{
			Name:    name,
			Timeout: 3 * time.Minute,
			Config: launcher.Config{
				Mode:  mode,
				Lobby: launcher.LobbyAuto,
				// fakegame reads no preferences; keep the user's folder untouched.
				Game:    launcher.GameConfig{Exe: fakegameExe, Prefs: seat.PrefsShared},
				ICE:     launcher.ICEConfig{Adapter: adapter},
				Players: players(n),
			},
			Steps: []Step{
				{Start: &UIDs{All: true}},
				{Host: 1},
				{Join: &UIDs{Others: true}},
				{WaitState: &WaitState{UIDs: UIDs{All: true}, State: "Launching", Timeout: time.Minute}},
				{Wait: 5 * time.Second},
			},
		}
	}
	noLoss := 0.0

	direct := base("selftest-direct-3p", launcher.ModeDirect, 3)
	direct.Expect = Expect{AllLaunched: true, NoCrash: true,
		PeerStats: &PeerStatsExpect{MinAnswered: 20, MaxAvgRTT: 20 * time.Millisecond, MaxLoss: &noLoss}}

	// 15% loss each way is ~28% per round trip. Over ~150 pings per link the
	// spread is ~3.6%, so the 10% floor sits >4 sigma away and cannot flake.
	lagged := base("selftest-relay-latency-loss", launcher.ModeRelay, 3)
	lagged.Link = relay.Impairment{Latency: 40 * time.Millisecond, Jitter: 5 * time.Millisecond, Loss: 0.15}
	lagged.Steps[len(lagged.Steps)-1] = Step{Wait: 15 * time.Second}
	lagged.Expect = Expect{AllLaunched: true, NoCrash: true,
		PeerStats: &PeerStatsExpect{MinAnswered: 50, MinAvgRTT: 70 * time.Millisecond,
			MaxAvgRTT: 130 * time.Millisecond, MinLoss: 0.10}}

	partition := base("selftest-relay-partition", launcher.ModeRelay, 2)
	partition.Steps = append(partition.Steps,
		Step{Isolate: 2},
		Step{Wait: 4 * time.Second},
		Step{Note: "link 1<->2 cut; answered counters must stall"},
		Step{Restore: 2},
		Step{Wait: 4 * time.Second},
	)
	partition.Expect = Expect{AllLaunched: true, NoCrash: true,
		PeerStats: &PeerStatsExpect{MinAnswered: 20, MinLoss: 0.2}}

	// Players closing their games must end the run, whether it is waiting or
	// sitting at the console. Both would otherwise run into their 1m timeout.
	closing := func(name string, last Step) *Scenario {
		sc := base(name, launcher.ModeDirect, 2)
		sc.Timeout = time.Minute
		for i := range sc.Players {
			sc.Players[i].Args = []string{"/exitafter", "2s"}
		}
		sc.Steps[len(sc.Steps)-1] = last
		sc.Expect = Expect{AllLaunched: true, Present: []Match{
			{Kind: journal.ProcExit, UID: 1, Cmd: "game"},
			{Kind: journal.ProcExit, UID: 2, Cmd: "game"},
			{Kind: journal.Note, Arg: "ending the run"},
		}}
		return sc
	}
	closeWait := closing("selftest-clients-close-during-wait", Step{Wait: 10 * time.Minute})
	closeConsole := closing("selftest-clients-close-at-console", Step{Interactive: true})

	out := []*Scenario{direct, lagged, partition, closeWait, closeConsole}
	if adapter != "" {
		// Loss is counted from the first answer on, so the pings the adapter
		// drops while its data channel opens do not count against the link.
		iceLoss := 0.02
		ice := base("selftest-ice-host-candidates", launcher.ModeICE, 2)
		ice.ICE.NoTurn = true
		ice.Expect = Expect{AllLaunched: true, NoCrash: true,
			PeerStats: &PeerStatsExpect{MinAnswered: 20, MaxAvgRTT: 50 * time.Millisecond, MaxLoss: &iceLoss}}

		turn := base("selftest-ice-turn-relay", launcher.ModeICE, 2)
		turn.ICE.ForceRelay = true
		turn.Expect = Expect{AllLaunched: true, NoCrash: true, MinTurnAllocations: 2, RelayOnly: true,
			PeerStats: &PeerStatsExpect{MinAnswered: 20, MaxAvgRTT: 50 * time.Millisecond, MaxLoss: &iceLoss}}
		out = append(out, ice, turn)
	}
	return out
}
