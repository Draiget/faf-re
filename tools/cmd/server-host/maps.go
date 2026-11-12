package main

import (
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// previewPath is a map's preview URL under base ("/api/v1/maps/" or "/api/v1/public/maps/").
func previewPath(base, id string) string { return base + url.PathEscape(id) + "/preview.png" }

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
	// Each start spot (the scenario's armies in order, from the _save.lua markers), as x and z over the map's size.
	Spawns [][2]float64 `json:"spawns"`
	// The path of its preview image (the one embedded in its .scmap) as PNG, when it has one.
	Preview string `json:"preview,omitempty"`

	optionsFile string
	scmapFile   string
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

// scenarioArmies is the standard configuration's army names in order (start spot n is the n-th).
func scenarioArmies(text string) []string {
	a := reArmies.FindStringSubmatch(text)
	if a == nil {
		return nil
	}
	var out []string
	for _, m := range reArmy.FindAllStringSubmatch(a[1], -1) {
		out = append(out, m[1])
	}
	return out
}

var (
	// A marker in a _save.lua: ['ARMY_1'] = { ['type'] = STRING( .. ), ['position'] = VECTOR3( x, y, z ), ... }. Its
	// body holds no braces, which keeps the Armies section's own ['ARMY_1'] = { ... Economy = { ... } } out.
	reMarker   = regexp.MustCompile(`\[\s*['"]([^'"\]]+)['"]\s*\]\s*=\s*\{([^{}]*)\}`)
	rePosition = regexp.MustCompile(`(?:\[\s*['"]position['"]\s*\]|\bposition)\s*=\s*VECTOR3\s*\(\s*([-+0-9.eE]+)\s*,\s*[-+0-9.eE]+\s*,\s*([-+0-9.eE]+)\s*\)`)
)

// parseSpawns finds each army's start marker in a _save.lua and gives its x and z over the map's size (0..1), in the
// armies' order; nil unless every army has one.
func parseSpawns(save string, armies []string, size [2]int) [][2]float64 {
	if len(armies) == 0 || size[0] <= 0 || size[1] <= 0 {
		return nil
	}
	want := map[string]int{}
	for i, a := range armies {
		want[a] = i
	}
	out := make([][2]float64, len(armies))
	found := make([]bool, len(armies))
	for _, m := range reMarker.FindAllStringSubmatch(save, -1) {
		i, ok := want[m[1]]
		if !ok || found[i] {
			continue
		}
		p := rePosition.FindStringSubmatch(m[2])
		if p == nil {
			continue
		}
		x, err1 := strconv.ParseFloat(p[1], 64)
		z, err2 := strconv.ParseFloat(p[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[i] = [2]float64{round4(clamp01(x / float64(size[0]))), round4(clamp01(z / float64(size[1])))}
		found[i] = true
	}
	for _, f := range found {
		if !f {
			return nil
		}
	}
	return out
}

func clamp01(v float64) float64 { return math.Max(0, math.Min(1, v)) }

func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

// mapExtras is what a map folder's other files add (start spots, the preview), kept while the files don't change: the
// map list is read again every minute and a _save.lua can be megabytes.
type mapExtras struct {
	stamp     string
	spawns    [][2]float64
	scmapFile string
	preview   bool
}

var (
	extrasMu    sync.Mutex
	extrasCache = map[string]mapExtras{}
)

// fileStamp is a file's size and change time, "" when it can't be read.
func fileStamp(path string) string {
	if path == "" {
		return ""
	}
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(st.Size(), 10) + "@" + strconv.FormatInt(st.ModTime().UnixNano(), 10)
}

// siblingFile finds <prefix><suffix> in dir, ignoring case (a scenario names Adaptive_Adrastea.scmap, the folder holds
// adaptive_adrastea.scmap); with several, the one whose case matches first.
func siblingFile(dir, prefix, suffix string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	exact := prefix + suffix
	found := ""
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if e.Name() == exact {
			return filepath.Join(dir, e.Name())
		}
		if found == "" && strings.EqualFold(e.Name(), exact) {
			found = filepath.Join(dir, e.Name())
		}
	}
	return found
}

var (
	reSaveField = regexp.MustCompile(`(?m)^\s*save\s*=\s*['"]([^'"]+)['"]`)
	reMapField  = regexp.MustCompile(`(?m)^\s*map\s*=\s*['"]([^'"]+)['"]`)
)

// scenarioFile is the file a scenario names in field re (save = '/maps/<folder>/<x>_save.lua'), found in dir; else
// <prefix><suffix> there.
func scenarioFile(dir, text string, re *regexp.Regexp, prefix, suffix string) string {
	if m := re.FindStringSubmatch(text); m != nil {
		base := m[1][strings.LastIndexAny(m[1], `/\`)+1:]
		if found := siblingFile(dir, base, ""); found != "" {
			return found
		}
	}
	return siblingFile(dir, prefix, suffix)
}

// extrasFor reads (or takes from the cache) a map's start spots and whether its .scmap holds a preview.
func extrasFor(scenarioPath, scenarioText string, size [2]int) mapExtras {
	dir := filepath.Dir(scenarioPath)
	prefix := strings.TrimSuffix(filepath.Base(scenarioPath), "_scenario.lua")
	savePath := scenarioFile(dir, scenarioText, reSaveField, prefix, "_save.lua")
	scmapPath := scenarioFile(dir, scenarioText, reMapField, prefix, ".scmap")
	if scmapPath == "" {
		if matches, _ := filepath.Glob(filepath.Join(dir, "*.scmap")); len(matches) == 1 {
			scmapPath = matches[0]
		}
	}
	stamp := fileStamp(scenarioPath) + "|" + fileStamp(savePath) + "|" + fileStamp(scmapPath)
	extrasMu.Lock()
	cached, ok := extrasCache[scenarioPath]
	extrasMu.Unlock()
	if ok && cached.stamp == stamp {
		return cached
	}
	x := mapExtras{stamp: stamp, scmapFile: scmapPath}
	if savePath != "" {
		if b, err := os.ReadFile(savePath); err == nil {
			x.spawns = parseSpawns(string(b), scenarioArmies(scenarioText), size)
		}
	}
	if scmapPath != "" {
		x.preview = scmapHasPreview(scmapPath)
	}
	extrasMu.Lock()
	extrasCache[scenarioPath] = x
	extrasMu.Unlock()
	return x
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
			x := extrasFor(files[0], string(b), size)
			mp.Spawns, mp.scmapFile = x.spawns, x.scmapFile
			if mp.Spawns == nil {
				mp.Spawns = [][2]float64{}
			}
			if x.preview {
				mp.Preview = previewPath("/api/v1/maps/", id)
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
