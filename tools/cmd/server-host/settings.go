package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Plan WP17.20: the settings a lobby can set, as FAF's Lua defines them: the server binary describes them
// (`server --describe-settings`, the engine running lobbyOptions.lua, aitypes.lua and a map's _options.lua).

// SettingValue is one choice of a setting; its key is a string or a number, as FAF has it.
type SettingValue struct {
	Key  any    `json:"key"`
	Text string `json:"text"`
	Help string `json:"help,omitempty"`
}

// Setting is one game or map option.
type Setting struct {
	Key     string         `json:"key"`
	Label   string         `json:"label"`
	Help    string         `json:"help,omitempty"`
	Default any            `json:"default"`
	Group   string         `json:"group"`
	Values  []SettingValue `json:"values"`
}

// AIType is one AI a seat can be.
type AIType struct {
	Key    string  `json:"key"`
	Name   string  `json:"name"`
	Rating float64 `json:"rating,omitempty"`
}

// Settings is the catalog GET /api/v1/settings answers.
type Settings struct {
	Options    []Setting `json:"options"`
	AI         []AIType  `json:"ai"`
	MapOptions []Setting `json:"map_options"`
}

// rawSettings is --describe-settings' JSON: FAF's tables as they are.
type rawSettings struct {
	Lobby struct {
		Global []rawOption `json:"globalOpts"`
		Team   []rawOption `json:"teamOptions"`
		AI     []rawOption `json:"AIOpts"`
	} `json:"lobby"`
	AI  []map[string]any `json:"ai"`
	Map []rawOption      `json:"map"`
}

type rawOption struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Help    string `json:"help"`
	Default any               `json:"default"`
	Values  []json.RawMessage `json:"values"` // records {key, text, help}, or plain strings or numbers
}

// rawValue reads one entry of an option's values: a {key, text, help} record, or a bare string or number that is
// both the key and the text (FAF writes e.g. a unit cap's values as plain strings).
func rawValue(raw json.RawMessage) (SettingValue, bool) {
	var record struct {
		Key  any    `json:"key"`
		Text string `json:"text"`
		Help string `json:"help"`
	}
	if err := json.Unmarshal(raw, &record); err == nil && record.Key != nil {
		return SettingValue{Key: record.Key, Text: stripLoc(record.Text), Help: stripLoc(record.Help)}, true
	}
	var scalar any
	if err := json.Unmarshal(raw, &scalar); err == nil && scalar != nil {
		switch scalar.(type) {
		case string, float64, bool:
			return SettingValue{Key: scalar, Text: stripLoc(fmt.Sprint(scalar))}, true
		}
	}
	return SettingValue{}, false
}

var reLocTag = regexp.MustCompile(`^<LOC [^>]*>`)

func stripLoc(s string) string { return reLocTag.ReplaceAllString(s, "") }

// convert turns FAF's option tables into settings: tags off the texts, and the default (FAF's 1-based index into
// the values) as the value's own key.
func convert(raw []rawOption, group string) []Setting {
	out := make([]Setting, 0, len(raw))
	for _, o := range raw {
		if o.Key == "" {
			continue
		}
		s := Setting{Key: o.Key, Label: stripLoc(o.Label), Help: stripLoc(o.Help), Group: group, Default: o.Default}
		for _, raw := range o.Values {
			if v, ok := rawValue(raw); ok {
				s.Values = append(s.Values, v)
			}
		}
		if index, ok := o.Default.(float64); ok && index >= 1 && int(index) <= len(s.Values) && index == float64(int(index)) {
			s.Default = s.Values[int(index)-1].Key
		}
		out = append(out, s)
	}
	return out
}

func parseSettings(data []byte) (Settings, error) {
	var raw rawSettings
	if err := json.Unmarshal(data, &raw); err != nil {
		return Settings{}, err
	}
	s := Settings{AI: []AIType{}, MapOptions: convert(raw.Map, "map")}
	s.Options = append(convert(raw.Lobby.Global, "rules"), convert(raw.Lobby.Team, "teams")...)
	s.Options = append(s.Options, convert(raw.Lobby.AI, "ai")...)
	for _, a := range raw.AI {
		key, _ := a["key"].(string)
		if key == "" {
			continue
		}
		name, _ := a["name"].(string)
		if name == "" {
			name = key
		}
		rating, _ := a["rating"].(float64)
		s.AI = append(s.AI, AIType{Key: key, Name: stripLoc(name), Rating: rating})
	}
	if len(s.Options) == 0 {
		return s, errors.New("the server described no lobby options")
	}
	return s, nil
}

// settingsSource runs the server binary to describe the settings, once for the game and once per map with its own
// options file, and keeps what it got.
type settingsSource struct {
	serverBin  string
	engineArgs []string
	workDir    string
	mu         sync.Mutex
	base       *Settings
	byMap      map[string]Settings
}

func (s *settingsSource) describe(optionsFile string) (Settings, error) {
	dir, err := os.MkdirTemp(s.workDir, "settings-")
	if err != nil {
		return Settings{}, err
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "settings.json")
	args := []string{"--describe-settings", out, "--out", dir}
	if optionsFile != "" {
		args = append(args, "--map-options-file", optionsFile)
	}
	args = append(args, s.engineArgs...)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.serverBin, args...)
	cmd.Dir = dir
	if text, err := cmd.CombinedOutput(); err != nil {
		return Settings{}, fmt.Errorf("server --describe-settings: %v: %s", err, lastLine(string(text)))
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return Settings{}, err
	}
	return parseSettings(data)
}

func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return lines[len(lines)-1]
}

// get answers the game's settings, with the map's own options when mapID names a map that has an options file.
func (s *settingsSource) get(m *Map) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.base == nil {
		base, err := s.describe("")
		if err != nil {
			return Settings{}, err
		}
		s.base = &base
	}
	out := *s.base
	out.MapOptions = []Setting{}
	if m == nil || m.optionsFile == "" {
		return out, nil
	}
	if cached, ok := s.byMap[m.ID]; ok {
		out.MapOptions = cached.MapOptions
		return out, nil
	}
	withMap, err := s.describe(m.optionsFile)
	if err != nil {
		return Settings{}, err
	}
	if s.byMap == nil {
		s.byMap = map[string]Settings{}
	}
	s.byMap[m.ID] = withMap
	out.MapOptions = withMap.MapOptions
	return out, nil
}
