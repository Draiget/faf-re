//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The package's programs need glibc 2.34 or newer (tools/release/linux/package.sh checks the build).
const minGlibcMajor, minGlibcMinor = 2, 34

func newSystem(o options) (*system, error) {
	if o.x86 {
		return nil, errors.New("--x86 is for Windows; the Linux engine is 64-bit only")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	faf := o.fafData
	if faf == "" {
		faf = fafDataFromPrefs(home)
	}
	if faf == "" {
		faf = filepath.Join(home, ".faforever")
	}
	dir := o.dir
	if dir == "" {
		data := os.Getenv("XDG_DATA_HOME")
		if data == "" {
			data = filepath.Join(home, ".local", "share")
		}
		dir = filepath.Join(data, "faf-re", "engine")
	}
	if faf, err = filepath.Abs(faf); err != nil {
		return nil, err
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return nil, err
	}
	return &system{goos: "linux", arch: "x64", fafData: faf, fafDataSet: o.fafData != "", installDir: dir,
		exeName: "ForgedAlliance", assetSuffix: "-linux-x64.tar.gz"}, nil
}

// launchArgs are faf-launch's arguments: only a FAF data folder given to setup, as faf-launch finds
// the default one by itself at every start (and follows the client when it moves).
func launchArgs(s *system) []string {
	if s.fafDataSet {
		return []string{"--faf-data", s.fafData}
	}
	return nil
}

// fafDataFromPrefs reads the data folder FAF's client uses ("baseDataDirectory" in client.prefs),
// as faf-launch does; the client may write it relative to the home folder.
func fafDataFromPrefs(home string) string {
	data, err := os.ReadFile(filepath.Join(home, ".faforever", "client.prefs"))
	if err != nil {
		return ""
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return ""
	}
	dir := findJSONString(v, "baseDataDirectory")
	switch {
	case dir == "":
		return ""
	case strings.HasPrefix(dir, "~/"):
		return filepath.Join(home, dir[2:])
	case !isDir(dir) && isDir(filepath.Join(home, dir)):
		return filepath.Join(home, dir)
	}
	return dir
}

func findJSONString(v any, key string) string {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t[key].(string); ok {
			return s
		}
		for _, child := range t {
			if s := findJSONString(child, key); s != "" {
				return s
			}
		}
	case []any:
		for _, child := range t {
			if s := findJSONString(child, key); s != "" {
				return s
			}
		}
	}
	return ""
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func platformChecks(s *system) []check {
	var out []check
	if v, err := glibcVersion(); err != nil {
		out = append(out, check{name: "glibc", detail: "can't tell the version: " + err.Error(),
			fix: []string{"The engine needs a glibc-based system (Ubuntu 22.04, Debian 12, Mint 21, RHEL 9 or newer)."}})
	} else if !glibcAtLeast(v, minGlibcMajor, minGlibcMinor) {
		out = append(out, check{name: "glibc", detail: fmt.Sprintf("%s, the engine needs %d.%d or newer", v, minGlibcMajor, minGlibcMinor),
			fix: []string{"Use Ubuntu 22.04, Debian 12, Mint 21, RHEL 9 or newer."}})
	} else {
		out = append(out, check{name: "glibc", ok: true, detail: v})
	}
	if vulkanLoader() {
		out = append(out, check{name: "Vulkan", ok: true, detail: "libvulkan.so.1 found"})
	} else {
		out = append(out, check{name: "Vulkan", warn: true, detail: "libvulkan.so.1 not found; the game draws with Vulkan",
			fix: []string{"Install your distribution's Vulkan loader and driver (e.g. libvulkan1 and mesa-vulkan-drivers)."}})
	}
	return out
}

// glibcVersion reads the version from `ldd --version` (musl's ldd exits 1 and prints to stderr,
// hence CombinedOutput and the error only when nothing came out).
func glibcVersion() (string, error) {
	out, err := exec.Command("ldd", "--version").CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", err
	}
	return parseLddVersion(string(out))
}

func vulkanLoader() bool {
	for _, dir := range []string{"/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib", "/lib/x86_64-linux-gnu", "/lib64"} {
		if fileExists(filepath.Join(dir, "libvulkan.so.1")) {
			return true
		}
	}
	out, err := exec.Command("ldconfig", "-p").Output()
	return err == nil && strings.Contains(string(out), "libvulkan.so.1")
}

func writeHint(s *system) []string {
	return []string{"Pick a folder you can write to with --dir DIR."}
}

func steamRoots() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(home, ".steam", "steam"),
		filepath.Join(home, ".local", "share", "Steam"),
		filepath.Join(home, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam"),
	}
}

func freeBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// engineRunning reports whether a process runs exe, from /proc/<pid>/exe.
func engineRunning(exe string) (bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		target, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err == nil && (target == exe || target == exe+" (deleted)") {
			return true, nil
		}
	}
	return false, nil
}

// createShortcuts adds a menu entry that starts faf-launch, which finds the game's files at each start.
func createShortcuts(s *system) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		data = filepath.Join(home, ".local", "share")
	}
	apps := filepath.Join(data, "applications")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		return nil, err
	}
	entry := filepath.Join(apps, "faf-re.desktop")
	cmdline := desktopQuote(filepath.Join(s.installDir, "faf-launch"))
	for _, a := range launchArgs(s) {
		cmdline += " " + desktopQuote(a)
	}
	text := "[Desktop Entry]\nType=Application\nName=Forged Alliance (faf-re)\n" +
		"Comment=The rebuilt Forged Alliance engine\n" +
		"Exec=" + cmdline + "\n" +
		"Path=" + s.installDir + "\nTerminal=false\nCategories=Game;StrategyGame;\n"
	if err := os.WriteFile(entry, []byte(text), 0o755); err != nil {
		return nil, err
	}
	return []string{entry}, nil
}

// desktopQuote quotes a path for a .desktop file's Exec key.
func desktopQuote(p string) string {
	r := strings.NewReplacer(`\`, `\\\\`, `"`, `\\"`, "`", "\\\\`", "$", `\\$`, "%", "%%")
	return `"` + r.Replace(p) + `"`
}

func afterInstall(s *system) {
	launch := filepath.Join(s.installDir, "faf-launch")
	out, err := exec.Command(launch, append([]string{"--show"}, launchArgs(s)...)...).CombinedOutput()
	fmt.Println("\nWhat faf-launch finds:")
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		fmt.Println("  " + line)
	}
	if err != nil {
		fmt.Printf("faf-launch --show failed (%v); the game won't start until what it names is fixed.\n", err)
		return
	}
	fmt.Printf("\nStart it from the menu (\"Forged Alliance (faf-re)\") or with:\n  %s\n",
		strings.Join(append([]string{launch}, launchArgs(s)...), " "))
	fmt.Println("If the game crashes, please attach its crash report and log to an issue at")
	fmt.Println("https://github.com/Draiget/scfa-re/issues.")
}

func pauseIfOwnConsole() {}
