package main

// `desync-diff compare`, also what `serve` writes to report.txt: the four steps, printed line for
// line as the Python desync_diff.py did (ported 2026-11-06, checked against it on 46 cases).

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The recorder's own switches differ between a live dump and a rebuilt one by design.
var recorderSwitches = map[string]bool{"sim_DesyncRecorder": true, "sim_DesyncRecorderMB": true, "sim_DesyncDumpBeat": true}

// Pacing switches headless sets for every replay run (ReplayRunner.cpp); they don't reach the sim.
var replayRunnerSwitches = map[string]bool{"sim_LeadOnSchedule": true}

// Dumps list these too (rendering, UI, camera, the user-side thread pool); players may set them
// differently without touching the sim, so a difference is shown but doesn't count.
var clientSwitchPrefixes = []string{"ren_", "ui_", "range_", "cam_", "user_", "sys_"}

var headerFields = [][2]string{
	{"build", "commit"}, {"build", "arch"}, {"build", "dirty"},
	{"game", "faf_game_version"}, {"game", "sim_fixes"}, {"game", "map"}, {"game", "game_mods_md5"},
	{"settings", "sim_ChecksumPeriod"}, {"settings", "sim_workers_in_use"}, {"settings", "sse2"},
	{"settings", "x87_control"}, {"settings", "mxcsr"},
	{"settings", "x87_control_at_start"}, {"settings", "mxcsr_at_start"},
}

var (
	hashLine    = regexp.MustCompile(`^\s+[0-9a-f]{32}$`)
	dirtyEntity = regexp.MustCompile(`^  0x([0-9a-f]{8})$`)
	entityRef   = regexp.MustCompile(`(?:Entity|Unit|Projectile|Weapon)\[0x([0-9a-f]{8})\]|^\s*0x([0-9a-f]{8})(?:'s |->)|\bfor 0x([0-9a-f]{8})\b`)
	armyBlock   = regexp.MustCompile(`^  "(.*)" \[(.*)\]$`)
	sectionLine = regexp.MustCompile(`^(Armies|Dirty Entities|\*{10} beat .*)$`)
	fieldLine   = regexp.MustCompile(`^\s*([A-Za-z_][\w\[\]]*)\s*[:=]`)
	callLine    = regexp.MustCompile(`->(\w+)\(|^\s*(\w+)\(`)
	tickLine    = regexp.MustCompile(`'s (\w+) tick`)
	stateEntity = regexp.MustCompile(`^0x([0-9a-f]{8}) bp=(\S*) army=(-?\d+)`)
	stateArmy   = regexp.MustCompile(`^  (\d+) "`)
)

// badInput is invalid input: exit 2 with "error: <text>".
type badInput struct{ text string }

func (e badInput) Error() string { return e.text }

// damaged is a dump that opened but is broken inside: exit 2 with "error: a dump is damaged (...)".
type damaged struct{ text string }

func (e damaged) Error() string { return e.text }

type stateBlocks struct {
	head   []string
	blocks map[string][]string
	order  []string
}

type dump struct {
	path    string
	label   string
	files   map[string][]byte
	header  map[string]any
	beats   []int
	armies  map[int]map[string]any
	sources map[int]string
	state   *stateBlocks
}

func decodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("extra data after the JSON value")
	}
	return value, nil
}

// readArchive returns the regular files of a .tar.gz or a .zip, by member name.
func readArchive(path string, data []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		reader := tar.NewReader(gz)
		for {
			member, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			if member.Typeflag != tar.TypeReg && member.Typeflag != tar.TypeRegA {
				continue
			}
			body, err := io.ReadAll(reader)
			if err != nil {
				return nil, err
			}
			files[member.Name] = body
		}
		return files, nil
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, member := range archive.File {
		handle, err := member.Open()
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(handle)
		handle.Close()
		if err != nil {
			return nil, err
		}
		files[member.Name] = body
	}
	return files, nil
}

// pyReprValue is repr() of a JSON value (for the format number).
func pyReprValue(value any) string {
	if s, ok := value.(string); ok {
		return pyRepr(s)
	}
	return pyStr(value)
}

func openDump(path string, data []byte) (*dump, error) {
	d := &dump{path: path, label: filepath.Base(path)}
	files, err := readArchive(path, data)
	if err == nil {
		d.files = files
		raw, ok := files["header.json"]
		if !ok {
			err = errors.New("'header.json'")
		} else {
			var value any
			value, err = decodeJSON(raw)
			if err == nil {
				if header, isMap := value.(map[string]any); isMap {
					d.header = header
				} else {
					err = errors.New("header.json is not an object")
				}
			}
		}
	}
	if err != nil {
		return nil, badInput{fmt.Sprintf("%s: not a desync dump (%s)", path, err)}
	}
	if format := d.header["format"]; !pyEqual(format, json.Number("1")) {
		return nil, badInput{fmt.Sprintf("%s: unknown dump format %s", path, pyReprValue(format))}
	}
	for name := range d.files {
		if strings.HasPrefix(name, "beats/beat") && strings.HasSuffix(name, ".log") && len(name) >= len("beats/beat")+len(".log") {
			beat, convErr := strconv.Atoi(name[len("beats/beat") : len(name)-len(".log")])
			if convErr != nil {
				return nil, damaged{fmt.Sprintf("ValueError: beat log name %s", pyRepr(name))}
			}
			d.beats = append(d.beats, beat)
		}
	}
	sort.Ints(d.beats)
	d.armies = map[int]map[string]any{}
	if list, ok := d.header["armies"].([]any); ok {
		for _, item := range list {
			army, isMap := item.(map[string]any)
			index, isInt := pyInt(army["index"])
			if !isMap || !isInt {
				return nil, damaged{"KeyError: 'index'"}
			}
			d.armies[index] = army
		}
	}
	d.sources = map[int]string{}
	if list, ok := d.header["command_sources"].([]any); ok {
		for _, item := range list {
			source, isMap := item.(map[string]any)
			index, isInt := pyInt(source["index"])
			if !isMap || !isInt {
				return nil, damaged{"KeyError: 'index'"}
			}
			d.sources[index] = pyStr(source["name"])
		}
	}
	return d, nil
}

func (d *dump) get(section, key string) any {
	group, _ := d.header[section].(map[string]any)
	return group[key]
}

func (d *dump) switches() map[string]string {
	text, _ := d.get("settings", "switches").(string)
	result := map[string]string{}
	for _, line := range splitLines(text) {
		if name, value, ok := strings.Cut(line, "="); ok {
			result[name] = value
		}
	}
	return result
}

func (d *dump) text(name string) []string {
	data, ok := d.files[name]
	if !ok {
		return nil
	}
	return splitLines(decodeText(data))
}

func (d *dump) beatLog(beat int) []string {
	return d.text(fmt.Sprintf("beats/beat%05d.log", beat))
}

type hashRow struct{ beat, source, name, reported, ours string }

func (d *dump) hashRows() ([]hashRow, error) {
	raw := d.text("hashes.csv")
	if len(raw) == 0 {
		return nil, nil
	}
	reader := csv.NewReader(strings.NewReader(strings.Join(raw, "\n")))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, damaged{"Error: " + err.Error()}
	}
	if len(records) == 0 {
		return nil, nil
	}
	column := map[string]int{}
	for i, name := range records[0] {
		if _, seen := column[name]; !seen {
			column[name] = i
		}
	}
	for _, need := range []string{"beat", "source", "name", "reported", "ours"} {
		if _, ok := column[need]; !ok {
			return nil, damaged{"KeyError: " + pyRepr(need)}
		}
	}
	field := func(record []string, name string) string {
		if i := column[name]; i < len(record) {
			return record[i]
		}
		return ""
	}
	var rows []hashRow
	for _, record := range records[1:] {
		rows = append(rows, hashRow{field(record, "beat"), field(record, "source"), field(record, "name"),
			field(record, "reported"), field(record, "ours")})
	}
	return rows, nil
}

// stateOf is state.txt as (header lines, blocks by key, keys in order).
func (d *dump) stateOf() *stateBlocks {
	if d.state != nil {
		return d.state
	}
	s := &stateBlocks{blocks: map[string][]string{}}
	part, key, haveKey := "head", "", false
	for _, line := range d.text("state.txt") {
		if line == "Armies" || line == "Entities" {
			part, haveKey = line, false
			continue
		}
		if part == "Armies" {
			if m := stateArmy.FindStringSubmatch(line); m != nil {
				key, haveKey = "army "+m[1], true
			}
		} else if part == "Entities" {
			if m := stateEntity.FindStringSubmatch(line); m != nil {
				key, haveKey = "0x"+m[1], true
			}
		}
		if !haveKey {
			s.head = append(s.head, line)
			continue
		}
		if _, ok := s.blocks[key]; !ok {
			s.order = append(s.order, key)
		}
		s.blocks[key] = append(s.blocks[key], line)
	}
	d.state = s
	return s
}

// entityInfo is (blueprint, army index) from state.txt.
func (d *dump) entityInfo(entity string) (string, int, bool) {
	block := d.stateOf().blocks["0x"+entity]
	if len(block) == 0 {
		return "", 0, false
	}
	m := stateEntity.FindStringSubmatch(block[0])
	army, _ := strconv.Atoi(m[3])
	return m[2], army, true
}

func (d *dump) armyName(index int) (string, error) {
	army, ok := d.armies[index]
	if !ok {
		return strconv.Itoa(index), nil
	}
	player, hasPlayer := army["player"]
	name, hasArmy := army["army"]
	if !hasPlayer {
		return "", damaged{"KeyError: 'player'"}
	}
	if !hasArmy {
		return "", damaged{"KeyError: 'army'"}
	}
	return fmt.Sprintf("%d %s [%s]", index, pyStr(player), pyStr(name)), nil
}

func (d *dump) describe() (string, error) {
	desync, _ := d.header["desync"].(map[string]any)
	local := -1
	if value, ok := d.header["local_army"]; ok {
		local, _ = pyInt(value)
	}
	who := "observer"
	if local >= 0 {
		name, err := d.armyName(local)
		if err != nil {
			return "", err
		}
		who = name
	}
	kind := "live game"
	if pyTruthy(d.get("game", "replay")) {
		kind = "replay run"
	}
	return fmt.Sprintf("%s: %s, %s, %s, dump at beat %s, first mismatch %s", d.label, pyStr(d.get("build", "identity")),
		who, kind, pyStr(desync["dump_beat"]), pyStr(desync["first_mismatched_beat"])), nil
}

type report struct{ strings.Builder }

func (r *report) line(format string, args ...any) {
	if len(args) == 0 {
		r.WriteString(format)
	} else {
		fmt.Fprintf(r, format, args...)
	}
	r.WriteByte('\n')
}

// say is one line printed as given.
func (r *report) say(text string) {
	r.WriteString(text)
	r.WriteByte('\n')
}

func (r *report) section(title string) {
	r.line("")
	r.say("== " + title)
}

func sameGame(r *report, dumps []*dump, force bool) error {
	idSet := map[string]bool{}
	for _, d := range dumps {
		if id := d.get("game", "faf_game_id"); pyTruthy(id) {
			idSet[pyStr(id)] = true
		}
	}
	if len(idSet) > 1 {
		message := "the dumps come from different FAF games: " + strings.Join(sortedKeys(idSet), ", ")
		if !force {
			return badInput{message + " (--force compares them anyway)"}
		}
		r.say("warning: " + message)
	}
	mapSet := map[string]bool{}
	playerSet := map[string][]string{}
	for _, d := range dumps {
		name, _ := d.get("game", "map").(string)
		if lowered := strings.ToLower(name); lowered != "" { // older dumps of a replay run had none
			mapSet[lowered] = true
		}
		var names []string
		for _, n := range d.sources {
			names = append(names, n)
		}
		sort.Strings(names)
		playerSet[strings.Join(names, "\x00")+"\x01"+strconv.Itoa(len(names))] = names
	}
	if len(mapSet) > 1 || len(playerSet) > 1 {
		var players [][]string
		for _, key := range sortedKeys(playerSet) {
			players = append(players, playerSet[key])
		}
		sort.SliceStable(players, func(i, j int) bool { return tupleLess(players[i], players[j]) })
		message := fmt.Sprintf("the dumps differ in map or players: %s / %s", pyReprList(sortedKeys(mapSet)), pyReprTupleList(players))
		if !force {
			return badInput{message + " (--force compares them anyway)"}
		}
		r.say("warning: " + message)
	}
	return nil
}

func tupleLess(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func compareHeaders(r *report, base, other *dump) bool {
	found := false
	for _, field := range headerFields {
		a, b := base.get(field[0], field[1]), other.get(field[0], field[1])
		if pyEqual(a, b) {
			continue
		}
		if a == nil || b == nil {
			// A field one dump's format doesn't have yet (written by an older recorder).
			r.line("  %s.%s: %s | %s (missing in one dump, not counted)", field[0], field[1], pyJSON(a), pyJSON(b))
		} else {
			r.line("  %s.%s: %s | %s", field[0], field[1], pyJSON(a), pyJSON(b))
			found = true
		}
	}
	sa, sb := base.switches(), other.switches()
	oneReplay := pyTruthy(base.get("game", "replay")) != pyTruthy(other.get("game", "replay"))
	names := map[string]bool{}
	for name := range sa {
		names[name] = true
	}
	for name := range sb {
		names[name] = true
	}
	for _, name := range sortedKeys(names) {
		if recorderSwitches[name] {
			continue
		}
		a, ok := sa[name]
		if !ok {
			a = "(absent)"
		}
		b, ok := sb[name]
		if !ok {
			b = "(absent)"
		}
		if a == b {
			continue
		}
		if oneReplay && replayRunnerSwitches[name] {
			r.line("  switch %s: %s | %s (set by the replay runner, not counted)", name, a, b)
			continue
		}
		client := false
		for _, prefix := range clientSwitchPrefixes {
			client = client || strings.HasPrefix(name, prefix)
		}
		if client {
			r.line("  switch %s: %s | %s (render, UI or thread setting, not counted)", name, a, b)
			continue
		}
		r.line("  switch %s: %s | %s", name, a, b)
		found = true
	}
	if !found {
		r.line("  no difference")
	}
	return found
}

// compareHashes prints who agrees with whom and returns the last agreed beat (ok false: none).
func compareHashes(r *report, dumps []*dump) (int, bool, error) {
	table := map[int]map[string]string{}
	for _, d := range dumps {
		rows, err := d.hashRows()
		if err != nil {
			return 0, false, err
		}
		for _, row := range rows {
			beat, err := strconv.Atoi(strings.TrimSpace(row.beat))
			if err != nil {
				return 0, false, damaged{fmt.Sprintf("ValueError: invalid literal for int() with base 10: %s", pyRepr(row.beat))}
			}
			name := row.name
			if name == "" {
				name = "source " + row.source
			}
			if table[beat] == nil {
				table[beat] = map[string]string{}
			}
			table[beat][name] = row.reported
			if pyTruthy(d.get("game", "replay")) {
				// A replay run is nobody's command source: its own hash is the "ours" column.
				table[beat][d.label+" (this run)"] = row.ours
			}
		}
	}
	beats := make([]int, 0, len(table))
	for beat := range table {
		beats = append(beats, beat)
	}
	sort.Ints(beats)
	lastAgreed, haveAgreed, firstDiff, haveDiff := 0, false, 0, false
	for _, beat := range beats {
		hashes := map[string]bool{}
		for _, digest := range table[beat] {
			hashes[digest] = true
		}
		if len(hashes) == 1 && len(table[beat]) > 1 {
			if !haveDiff {
				lastAgreed, haveAgreed = beat, true
			}
		} else if len(hashes) > 1 && !haveDiff {
			firstDiff, haveDiff = beat, true
		}
	}
	if haveAgreed {
		r.line("  last beat every hash matched: %d", lastAgreed)
	} else {
		r.line("  last beat every hash matched: none in the dumps")
	}
	if !haveDiff {
		r.line("  no beat with differing hashes")
		return lastAgreed, haveAgreed, nil
	}
	type group struct {
		digest string
		names  []string
	}
	var groups []*group
	byDigest := map[string]*group{}
	row := table[firstDiff]
	for _, name := range sortedKeys(row) {
		digest := row[name]
		g := byDigest[digest]
		if g == nil {
			g = &group{digest: digest}
			byDigest[digest] = g
			groups = append(groups, g)
		}
		g.names = append(g.names, name)
	}
	sizes := make([]int, len(groups))
	for i, g := range groups {
		sizes[i] = len(g.names)
	}
	sort.Ints(sizes)
	var shape string
	switch {
	case len(groups) == 2 && sizes[0] == 1 && sizes[1] == 1:
		shape = "the two differ"
	case len(groups) == 2 && sizes[0] == 1:
		shape = "one off, the rest agree"
	default:
		shape = fmt.Sprintf("a split into %d groups", len(groups))
	}
	r.line("  first beat with differing hashes: %d (%s)", firstDiff, shape)
	// sorted(groups.items(), key=-len): the dict is in first-seen order, and the sort is stable.
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i].names) > len(groups[j].names) })
	for _, g := range groups {
		r.line("    %s: %s", g.digest, strings.Join(g.names, ", "))
	}
	return lastAgreed, haveAgreed, nil
}

// lineField is what the line at index is about: a field name, a call, or the hash after a line.
func lineField(lines []string, index int) string {
	line := lines[index]
	if hashLine.MatchString(line) {
		low := index - 20
		if low < -1 {
			low = -1
		}
		for back := index - 1; back > low; back-- {
			if !hashLine.MatchString(lines[back]) {
				return fmt.Sprintf("the running hash after %s: a value hashed but not printed in full", pyRepr(pyStrip(lines[back])))
			}
		}
		return "running hash"
	}
	if m := tickLine.FindStringSubmatch(line); m != nil {
		return m[1] + " tick"
	}
	if m := fieldLine.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := callLine.FindStringSubmatch(line); m != nil {
		if m[1] != "" {
			return m[1]
		}
		return m[2]
	}
	return pyStrip(line)
}

// lineSubject is the entity or army the line at index belongs to.
func lineSubject(d, other *dump, lines []string, index int) (string, error) {
	for back := index; back >= 0; back-- {
		line := lines[back]
		entity := ""
		if m := entityRef.FindStringSubmatch(line); m != nil {
			for _, g := range m[1:] {
				if g != "" {
					entity = g
					break
				}
			}
		} else if m := dirtyEntity.FindStringSubmatch(line); m != nil {
			entity = m[1]
		}
		if entity != "" {
			blueprint, army, haveArmy := "", 0, false
			if dirtyEntity.MatchString(line) {
				end := back + 12
				if end > len(lines) {
					end = len(lines)
				}
				for ahead := back + 1; ahead < end; ahead++ {
					if dirtyEntity.MatchString(lines[ahead]) || sectionLine.MatchString(lines[ahead]) {
						break
					}
					if stripped := pyStrip(lines[ahead]); strings.HasPrefix(stripped, "bp:") {
						blueprint = stripped[3:]
					}
				}
			}
			bp, armyIndex, ok := d.entityInfo(entity)
			if !ok {
				bp, armyIndex, ok = other.entityInfo(entity)
			}
			if ok {
				if blueprint == "" {
					blueprint = bp
				}
				army, haveArmy = armyIndex, true
			}
			text := "entity 0x" + entity
			if blueprint != "" {
				text += " bp=" + blueprint
			}
			if haveArmy {
				name, err := d.armyName(army)
				if err != nil {
					return "", err
				}
				text += " army " + name
			} else {
				// EntityId: family in the top 4 bits, the army (source) in the next 8, 0xFF for none.
				id, _ := strconv.ParseUint(entity, 16, 32)
				if source := (id >> 20) & 0xFF; source == 0xFF {
					text += " army none"
				} else {
					text += fmt.Sprintf(" army %d (from its id)", source)
				}
			}
			return text, nil
		}
		if m := armyBlock.FindStringSubmatch(line); m != nil {
			return fmt.Sprintf("army %s [%s] (economy)", m[1], m[2]), nil
		}
		if sectionLine.MatchString(line) && back != index {
			break
		}
	}
	return "no entity or army (sim-wide line)", nil
}

func intSet(values []int) map[int]bool {
	set := map[int]bool{}
	for _, v := range values {
		set[v] = true
	}
	return set
}

func lineAt(lines []string, index int, missing string) string {
	if index < len(lines) {
		return lines[index]
	}
	return missing
}

func slice(lines []string, from, to int) []string {
	if from < 0 {
		from = 0
	}
	if to > len(lines) {
		to = len(lines)
	}
	if from >= to {
		return nil
	}
	return lines[from:to]
}

func compareLogs(r *report, base, other *dump, start int, context int) (bool, error) {
	inBase, inOther := intSet(base.beats), intSet(other.beats)
	var beats, missing []int
	for _, b := range base.beats {
		if inOther[b] {
			if b == 0 && start == 0 || b >= start {
				beats = append(beats, b)
			}
		} else {
			missing = append(missing, b)
		}
	}
	for _, b := range other.beats {
		if !inBase[b] {
			missing = append(missing, b)
		}
	}
	sort.Ints(missing)
	if len(beats) == 0 {
		r.line("  no beat log in both dumps from beat %d on", start)
		return false, nil
	}
	var only []int
	for _, b := range missing {
		if b >= start {
			only = append(only, b)
		}
	}
	if len(only) > 0 {
		r.line("  beats in one dump only (not compared): %s", compact(only))
	}
	r.line("  comparing beats %d..%d", beats[0], beats[len(beats)-1])
	for _, beat := range beats {
		la, lb := base.beatLog(beat), other.beatLog(beat)
		if equalLines(la, lb) {
			continue
		}
		total := max(len(la), len(lb))
		index, a, b := 0, "", ""
		for index = 0; index < total; index++ {
			a, b = lineAt(la, index, "(end of log)"), lineAt(lb, index, "(end of log)")
			if a != b {
				break
			}
		}
		if index == total { // no break: Python leaves the loop variable on the last index
			index = total - 1
		}
		lines := la
		if index >= len(la) {
			lines = lb
		}
		at := min(index, len(lines)-1)
		subject, err := lineSubject(base, other, lines, at)
		if err != nil {
			return false, err
		}
		r.line("  first difference: beat %d, line %d", beat, index+1)
		r.line("  about: %s", subject)
		r.line("  field: %s", lineField(lines, at))
		r.line("")
		for _, line := range slice(la, index-context, index) {
			r.say("    " + line)
		}
		r.say("  A " + a)
		r.say("  B " + b)
		for _, side := range []struct {
			name  string
			lines []string
		}{{"A", la}, {"B", lb}} {
			following := slice(side.lines, index+1, index+1+context)
			if len(following) > 0 {
				r.line("    -- then on %s:", side.name)
				for _, line := range following {
					r.say("    " + line)
				}
			}
		}
		return true, nil
	}
	r.line("  no difference in %d beats", len(beats))
	return false, nil
}

func equalLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func compareStates(r *report, base, other *dump, limit int) bool {
	sa, sb := base.stateOf(), other.stateOf()
	if len(sa.order) == 0 && len(sb.order) == 0 {
		r.line("  no state.txt in the dumps")
		return false
	}
	headA, headB := slice(sa.head, 0, 1), slice(sb.head, 0, 1)
	headsDiffer := !equalLines(headA, headB)
	if headsDiffer {
		r.line("  snapshots taken at different beats: %s | %s", pyReprList(headA), pyReprList(headB))
	}
	var onlyA, onlyB, differing []string
	for _, k := range sa.order {
		if _, ok := sb.blocks[k]; !ok {
			onlyA = append(onlyA, k)
		} else if !equalLines(sa.blocks[k], sb.blocks[k]) {
			differing = append(differing, k)
		}
	}
	for _, k := range sb.order {
		if _, ok := sa.blocks[k]; !ok {
			onlyB = append(onlyB, k)
		}
	}
	countEntities := func(keys []string) int {
		n := 0
		for _, k := range keys {
			if strings.HasPrefix(k, "0x") {
				n++
			}
		}
		return n
	}
	r.line("  entities: %d in A, %d in B; %d differ, %d in A only, %d in B only",
		countEntities(sa.order), countEntities(sb.order), countEntities(differing), countEntities(onlyA), countEntities(onlyB))
	var armies []string
	for _, k := range differing {
		if strings.HasPrefix(k, "army ") {
			armies = append(armies, k)
		}
	}
	if len(armies) > 0 {
		r.line("  armies that differ: %s", strings.Join(armies, ", "))
	}
	for _, side := range []struct {
		label  string
		keys   []string
		blocks map[string][]string
	}{{"A", onlyA, sa.blocks}, {"B", onlyB, sb.blocks}} {
		if len(side.keys) == 0 {
			continue
		}
		var firsts []string
		for _, k := range side.keys[:min(limit, len(side.keys))] {
			firsts = append(firsts, pyStrip(side.blocks[k][0]))
		}
		r.line("  in %s only: %s", side.label, strings.Join(firsts, "; "))
	}
	for _, key := range differing[:min(max(limit, 0), len(differing))] {
		a, b := sa.blocks[key], sb.blocks[key]
		for index := 0; index < max(len(a), len(b)); index++ {
			la, lb := lineAt(a, index, "(none)"), lineAt(b, index, "(none)")
			if la != lb {
				rest := ""
				if strings.HasPrefix(key, "0x") {
					rest = pyStrip(a[0][len(key):])
				}
				r.line("  %s %s", key, rest)
				r.say("    A " + pyStrip(la))
				r.say("    B " + pyStrip(lb))
				break
			}
		}
	}
	if len(differing) > limit {
		r.line("  ... %d more", len(differing)-limit)
	}
	return len(onlyA) > 0 || len(onlyB) > 0 || len(differing) > 0 || headsDiffer
}

func compact(beats []int) string {
	var runs []string
	for i := 0; i < len(beats); {
		j := i
		for j+1 < len(beats) && beats[j+1] == beats[j]+1 {
			j++
		}
		if i == j {
			runs = append(runs, strconv.Itoa(beats[i]))
		} else {
			runs = append(runs, fmt.Sprintf("%d-%d", beats[i], beats[j]))
		}
		i = j + 1
	}
	return strings.Join(runs, ", ")
}

// compareDumps runs the four steps and returns the report text and the exit code:
// 0 nothing differs, 1 a difference was found, 2 invalid input (the error line ends the text).
func compareDumps(paths []string, read func(string) ([]byte, error), context, states int, force bool) (string, int) {
	r := &report{}
	code, err := compareInto(r, paths, read, context, states, force)
	if err != nil {
		var bad badInput
		if errors.As(err, &bad) {
			r.line("error: %s", bad.text)
		} else {
			r.line("error: a dump is damaged (%s)", err.Error())
		}
		return r.String(), 2
	}
	return r.String(), code
}

func compareInto(r *report, paths []string, read func(string) ([]byte, error), context, states int, force bool) (int, error) {
	if len(paths) < 2 {
		return 2, badInput{"compare needs two dumps or more"}
	}
	var dumps []*dump
	for _, path := range paths {
		data, err := read(path)
		if err != nil {
			return 2, badInput{fmt.Sprintf("%s: not a desync dump (%s)", path, err)}
		}
		d, err := openDump(path, data)
		if err != nil {
			return 2, err
		}
		dumps = append(dumps, d)
	}
	if err := sameGame(r, dumps, force); err != nil {
		return 2, err
	}
	r.line("Dumps (A is the first; every other is B against it):")
	for _, d := range dumps {
		text, err := d.describe()
		if err != nil {
			return 2, err
		}
		r.say("  " + text)
	}
	found := false

	r.section("1. Header")
	for _, other := range dumps[1:] {
		if len(dumps) > 2 {
			r.line(" %s:", other.label)
		}
		found = compareHeaders(r, dumps[0], other) || found
	}

	r.section("2. Hashes")
	// What the game's players reported, merged from every dump: it tells where to look, but it is
	// the same in two copies of one dump, so it doesn't count as a difference between the dumps.
	lastAgreed, _, err := compareHashes(r, dumps)
	if err != nil {
		return 2, err
	}

	r.section("3. Beat logs")
	for _, other := range dumps[1:] {
		if len(dumps) > 2 {
			r.line(" %s:", other.label)
		}
		differs, err := compareLogs(r, dumps[0], other, lastAgreed, context)
		if err != nil {
			return 2, err
		}
		found = differs || found
	}

	r.section("4. State snapshot")
	for _, other := range dumps[1:] {
		if len(dumps) > 2 {
			r.line(" %s:", other.label)
		}
		found = compareStates(r, dumps[0], other, states) || found
	}

	r.line("")
	if found {
		r.line("Result: the dumps differ")
		return 1, nil
	}
	r.line("Result: no difference between the dumps")
	return 0, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
