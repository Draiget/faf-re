package main

import (
	"fmt"
	"math"
)

// Hint is the cost of one game, in cores, for a map size and player count.
type Hint struct {
	Players        int     `json:"players"`
	KM             int     `json:"km"`
	MeanCores      float64 `json:"mean_cores"`
	WorstCores     float64 `json:"worst_cores"`
	SuggestedCores int     `json:"suggested_cores"`
	Basis          string  `json:"basis"`
	// Plan WPR.8: the published minimums (WPR.7, measured on whole recorded games through the server, the largest
	// 10 s window): what each player needs down, what the server sends up, and the most players a game takes.
	MinConnectionKBps int    `json:"min_connection_kbps"`
	ServerUploadKBps  int    `json:"server_upload_kbps"`
	MaxPlayers        int    `json:"max_players"`
	ConnectionBasis   string `json:"connection_basis"`
}

// connectionFor is WPR.7's measurement for a game of this many players: per player 165 KB/s in a 1v1 and 360 KB/s
// in 8- and 16-player games; server upload 205 KB/s, 2.3 MB/s and 2.6 MB/s. Sizes in between take the larger game's.
func connectionFor(players int) (perPlayer, server int, basis string) {
	switch {
	case players <= 2:
		return 165, 205, "measured on a recorded 1v1 played through the server (largest 10 s window, WPR.7)"
	case players <= 8:
		return 360, 2300, "measured on a recorded 8-player game played through the server (largest 10 s window, WPR.7); smaller games use it as an upper bound"
	default:
		return 360, 2600, "measured on a recorded 16-player game played through the server (largest 10 s window, WPR.7)"
	}
}

// kMaxPlayers is the most players a game takes (the engine's 16 armies).
const kMaxPlayers = 16

// Measured on a two-socket test server (Xeon Gold 6144, one sim thread, game speed 0): side-by-side paced replays of
// FAF games, the mean and the worst 30 s per player bucket (the capacity load test of 2026-11-04).
var hintBuckets = []struct {
	maxPlayers  int
	label       string
	mean, worst float64
}{
	{2, "1-2", 0.066, 0.144},
	{5, "3-5", 0.247, 0.578},
	{8, "6-8", 0.220, 0.402},
	{math.MaxInt, "9+", 0.381, 0.668},
}

// sizeFactor is an estimate (not measured): bigger maps have longer paths and more reclaim.
func sizeFactor(km int) float64 {
	switch {
	case km <= 10:
		return 1.0
	case km <= 20:
		return 1.15
	case km <= 40:
		return 1.3
	default:
		return 1.5
	}
}

func hintFor(players, km int) Hint {
	if players < 1 {
		players = 1
	}
	b := hintBuckets[len(hintBuckets)-1]
	for _, c := range hintBuckets {
		if players <= c.maxPlayers {
			b = c
			break
		}
	}
	f := sizeFactor(km)
	h := Hint{Players: players, KM: km, MeanCores: math.Round(b.mean*f*1000) / 1000, WorstCores: math.Round(b.worst*f*1000) / 1000}
	h.SuggestedCores = int(math.Ceil(h.WorstCores))
	if h.SuggestedCores < 1 {
		h.SuggestedCores = 1
	}
	h.MinConnectionKBps, h.ServerUploadKBps, h.ConnectionBasis = connectionFor(players)
	h.MaxPlayers = kMaxPlayers
	h.Basis = fmt.Sprintf("measured on a two-socket test server (Xeon Gold 6144, one sim thread, game speed 0) from FAF replays: %s players mean %.3f, worst 30 s %.3f cores; the map size factor %.2f is an estimate, not measured; the server's views per player add to it",
		b.label, b.mean, b.worst, f)
	return h
}
