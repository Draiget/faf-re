package main

import (
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Map is one playable map found in a maps folder.
type Map struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	File        string `json:"file"` // the ScenarioFile the server loads: /maps/<folder>/<file>
	Size        [2]int `json:"size"`
	KM          int    `json:"km"`
	Players     int    `json:"players"`
	Description string `json:"description"`
	Source      string `json:"source"`
	HasOptions  bool   `json:"has_options"` // plan WP17.20: its own <map>_options.lua (adaptive maps)

	optionsFile string
}

var (
	reName    = regexp.MustCompile(`(?m)^\s*name\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')`)
	reDesc    = regexp.MustCompile(`(?m)^\s*description\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')`)
	reSize    = regexp.MustCompile(`size\s*=\s*\{\s*(\d+)\s*,\s*(\d+)\s*\}`)
	reArmies  = regexp.MustCompile(`armies\s*=\s*\{([^}]*)\}`)
	reArmy    = regexp.MustCompile(`['"]([^'"]+)['"]`)
	reLoc     = regexp.MustCompile(`^<LOC [^>]*>`)
	reType    = regexp.MustCompile(`(?m)^\s*type\s*=\s*['"]([a-z_]+)['"]`)
	reKMRound = []int{5, 10, 20, 40, 81}
)

func firstGroup(m []string) string {
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

// parseScenario reads what the API needs from a *_scenario.lua: name, description, size and the
// standard configuration's armies. It doesn't run Lua; a file it can't read gives ok false.
func parseScenario(text string) (name, desc string, size [2]int, players int, ok bool) {
	if m := reType.FindStringSubmatch(text); m != nil && m[1] != "skirmish" {
		return "", "", size, 0, false
	}
	m := reName.FindStringSubmatch(text)
	s := reSize.FindStringSubmatch(text)
	a := reArmies.FindStringSubmatch(text)
	if m == nil || s == nil || a == nil {
		return "", "", size, 0, false
	}
	name = reLoc.ReplaceAllString(firstGroup(m), "")
	if d := reDesc.FindStringSubmatch(text); d != nil {
		desc = reLoc.ReplaceAllString(firstGroup(d), "")
	}
	size[0], _ = strconv.Atoi(s[1])
	size[1], _ = strconv.Atoi(s[2])
	players = len(reArmy.FindAllString(a[1], -1))
	return name, desc, size, players, players > 0 && size[0] > 0
}

// kmOf is the map's size in the units the game's lobby shows (256 = 5 km).
func kmOf(size [2]int) int {
	side := size[0]
	if size[1] > side {
		side = size[1]
	}
	km := float64(side) / 51.2
	best := reKMRound[0]
	for _, v := range reKMRound {
		if math.Abs(float64(v)-km) < math.Abs(float64(best)-km) {
			best = v
		}
	}
	return best
}

// scanMaps lists the maps in each folder (every <folder>/<x>_scenario.lua one level down).
// The folder's label ("fa", "vault") becomes each map's source.
func scanMaps(dirs []mapDir) []Map {
	var out []Map
	seen := map[string]bool{}
	for _, d := range dirs {
		entries, err := os.ReadDir(d.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			files, _ := filepath.Glob(filepath.Join(d.path, e.Name(), "*_scenario.lua"))
			if len(files) == 0 {
				continue
			}
			b, err := os.ReadFile(files[0])
			if err != nil {
				continue
			}
			name, desc, size, players, ok := parseScenario(string(b))
			id := strings.ToLower(e.Name())
			if !ok || seen[id] {
				continue
			}
			seen[id] = true
			mp := Map{ID: id, Name: name, File: "/maps/" + e.Name() + "/" + filepath.Base(files[0]),
				Size: size, KM: kmOf(size), Players: players, Description: desc, Source: d.label}
			if opts := strings.TrimSuffix(files[0], "_scenario.lua") + "_options.lua"; opts != files[0] {
				if _, err := os.Stat(opts); err == nil {
					mp.HasOptions, mp.optionsFile = true, opts
				}
			}
			out = append(out, mp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out
}

type mapDir struct{ label, path string }
