package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// system is what setup knows about this computer and where the engine goes.
type system struct {
	goos        string // "windows" or "linux"
	arch        string // "x64" or "x86"
	fafData     string // FAF's data folder: bin/init_faf.lua, gamedata/*.nx2, fa_path.lua
	fafDataSet  bool   // given with --faf-data, so the Linux launcher is told it too
	installDir  string
	exeName     string // the engine's executable inside installDir
	assetSuffix string // release asset name after "faf-engine-<tag>"
	// faInstall is the Forged Alliance folder found by the checks (empty until then).
	faInstall string
}

// minFreeBytes is the space an install needs: the package unpacked, plus the download.
const minFreeBytes = 400 << 20

type check struct {
	name   string
	ok     bool
	warn   bool // not ok, but the install can go on
	detail string
	fix    []string
}

func runChecks(s *system) []check {
	var out []check
	add := func(c check) { out = append(out, c) }

	// FAF's data folder, which the FAF client fills when it first starts a game or replay.
	clientHint := []string{
		"Install FAF's client (https://faforever.com) and start one game or replay with it,",
		"so it downloads the game data; or name the folder with --faf-data DIR.",
	}
	if st, err := os.Stat(s.fafData); err != nil || !st.IsDir() {
		add(check{name: "FAF's data folder", detail: s.fafData + " not found", fix: clientHint})
		return out
	}
	add(check{name: "FAF's data folder", ok: true, detail: s.fafData})
	initFile := filepath.Join(s.fafData, "bin", "init_faf.lua")
	if fileExists(initFile) {
		add(check{name: "FAF's init file", ok: true, detail: initFile})
	} else {
		add(check{name: "FAF's init file", detail: initFile + " is missing", fix: clientHint})
	}
	if n := countGlob(filepath.Join(s.fafData, "gamedata", "*.nx2")); n > 0 {
		add(check{name: "FAF's game data", ok: true, detail: fmt.Sprintf("%d .nx2 files in %s", n, filepath.Join(s.fafData, "gamedata"))})
	} else {
		add(check{name: "FAF's game data", detail: "no .nx2 files in " + filepath.Join(s.fafData, "gamedata"), fix: clientHint})
	}

	// Forged Alliance itself, from the path FAF's client wrote into fa_path.lua.
	add(faInstallCheck(s))

	out = append(out, platformChecks(s)...)

	// The install folder: writable, with room, and the engine in it not running.
	if err := checkWritable(s.installDir); err != nil {
		add(check{name: "Install folder", detail: err.Error(), fix: writeHint(s)})
	} else {
		add(check{name: "Install folder", ok: true, detail: s.installDir})
	}
	if free, err := freeBytes(existingParent(s.installDir)); err == nil {
		if free < minFreeBytes {
			add(check{name: "Free space", detail: fmt.Sprintf("%d MB free, %d MB needed", free>>20, minFreeBytes>>20)})
		} else {
			add(check{name: "Free space", ok: true, detail: fmt.Sprintf("%d MB free", free>>20)})
		}
	}
	exe := filepath.Join(s.installDir, s.exeName)
	switch running, err := engineRunning(exe); {
	case err != nil:
		add(check{name: "Engine not running", warn: true, detail: "can't tell: " + err.Error(),
			fix: []string{"Close the game if it is running; setup stops without changes if it can't replace the exe."}})
	case running:
		add(check{name: "Engine not running", detail: exe + " is running", fix: []string{"Close the game, then run setup again."}})
	default:
		add(check{name: "Engine not running", ok: true, detail: "not running"})
	}
	return out
}

// parseLddVersion takes glibc's version from the first line of `ldd --version`, which ends with it
// ("ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39"). musl's ldd prints "musl libc ..." instead.
func parseLddVersion(out string) (string, error) {
	first, _, _ := strings.Cut(out, "\n")
	lower := strings.ToLower(first)
	fields := strings.Fields(first)
	if len(fields) == 0 || (!strings.Contains(lower, "glibc") && !strings.Contains(lower, "gnu libc")) {
		return "", fmt.Errorf("not glibc: %q", strings.TrimSpace(first))
	}
	return fields[len(fields)-1], nil
}

// glibcAtLeast compares a "2.39"-style version with major.minor.
func glibcAtLeast(v string, major, minor int) bool {
	a, b, _ := strings.Cut(v, ".")
	ma, err1 := strconv.Atoi(a)
	b, _, _ = strings.Cut(b, ".")
	mi, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return ma > major || (ma == major && mi >= minor)
}

func faInstallCheck(s *system) check {
	const name = "Forged Alliance"
	faPathLua := filepath.Join(s.fafData, "fa_path.lua")
	recorded := ""
	if v, err := readLuaString(faPathLua, "fa_path"); err == nil {
		recorded = v
	}
	if recorded != "" && isFAInstall(recorded) {
		s.faInstall = filepath.Clean(recorded)
		return check{name: name, ok: true, detail: s.faInstall}
	}
	found := findFAInSteam()
	if s.goos == "linux" && found != "" {
		// faf-launch looks in Steam's libraries itself when fa_path.lua has nothing usable.
		s.faInstall = found
		return check{name: name, ok: true, detail: found + " (Steam)"}
	}
	c := check{name: name}
	switch {
	case recorded != "":
		c.detail = "fa_path.lua names " + recorded + ", which has no gamedata folder"
	case fileExists(faPathLua):
		c.detail = faPathLua + " names no game folder"
	default:
		c.detail = faPathLua + " is missing"
	}
	c.fix = []string{"Set the Forged Alliance folder in FAF's client (Settings, Forged Alliance) and start"}
	c.fix = append(c.fix, "one game or replay with it, so it writes fa_path.lua.")
	if found != "" {
		c.fix = append(c.fix, "Found a copy in Steam's library: "+found)
	}
	return c
}

func printChecks(results []check) (failed int) {
	for _, c := range results {
		mark := "[ok]"
		switch {
		case !c.ok && c.warn:
			mark = "[--]"
		case !c.ok:
			mark = "[!!]"
			failed++
		}
		fmt.Printf("  %s %s: %s\n", mark, c.name, c.detail)
		if !c.ok {
			for _, line := range c.fix {
				fmt.Printf("       %s\n", line)
			}
		}
	}
	return failed
}

// isFAInstall reports whether dir looks like a Forged Alliance install: it has a gamedata folder.
func isFAInstall(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "gamedata"))
	return err == nil && st.IsDir()
}

// readLuaString reads `name = "value"` from a Lua file such as FAF's fa_path.lua, with Lua's
// backslash escapes undone.
func readLuaString(path, name string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok || strings.TrimSpace(key) != name {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) < 2 || (value[0] != '"' && value[0] != '\'') || value[len(value)-1] != value[0] {
			continue
		}
		return unescape(value[1 : len(value)-1]), nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New(name + " not found in " + path)
}

// unescape undoes the backslash escapes of a Lua or VDF string: \\ \" \' \n \t.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// steamLibraries reads the library folders from Steam's libraryfolders.vdf: every "path" value.
func steamLibraries(vdf string) []string {
	var out []string
	for _, line := range strings.Split(vdf, "\n") {
		fields := quotedFields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "path") {
			out = append(out, unescape(fields[1]))
		}
	}
	return out
}

// quotedFields returns the "..." strings on a VDF line, escapes kept.
func quotedFields(line string) []string {
	var out []string
	for i := 0; i < len(line); i++ {
		if line[i] != '"' {
			continue
		}
		j := i + 1
		for ; j < len(line) && line[j] != '"'; j++ {
			if line[j] == '\\' {
				j++
			}
		}
		if j >= len(line) {
			break
		}
		out = append(out, line[i+1:j])
		i = j
	}
	return out
}

// findFAInSteam looks for Forged Alliance in every Steam library this system knows of.
func findFAInSteam() string {
	for _, root := range steamRoots() {
		libraries := []string{root}
		if data, err := os.ReadFile(filepath.Join(root, "steamapps", "libraryfolders.vdf")); err == nil {
			libraries = append(libraries, steamLibraries(string(data))...)
		}
		for _, lib := range libraries {
			dir := filepath.Join(lib, "steamapps", "common", "Supreme Commander Forged Alliance")
			if isFAInstall(dir) {
				return dir
			}
		}
	}
	return ""
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func countGlob(pattern string) int {
	m, _ := filepath.Glob(pattern)
	return len(m)
}

// existingParent returns dir or its nearest parent that exists, for asking about free space.
func existingParent(dir string) string {
	for {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}

// checkWritable writes and removes a file in dir, or in its nearest existing parent when dir doesn't
// exist yet, so a check run leaves nothing behind.
func checkWritable(dir string) error {
	target := existingParent(dir)
	if st, err := os.Stat(target); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not a folder", target)
	}
	f, err := os.CreateTemp(target, ".scfa-re-setup-*")
	if err != nil {
		return fmt.Errorf("can't write into %s: %w", target, err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
