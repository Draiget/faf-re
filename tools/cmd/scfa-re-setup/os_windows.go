//go:build windows

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func newSystem(o options) (*system, error) {
	faf := o.fafData
	if faf == "" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		faf = filepath.Join(pd, "FAForever")
	}
	faf, err := filepath.Abs(faf)
	if err != nil {
		return nil, err
	}
	s := &system{goos: "windows", fafData: faf, arch: "x64", exeName: "main_x64.exe", assetSuffix: "-x64.zip",
		installDir: filepath.Join(faf, "bin_x64")}
	if o.x86 {
		// The 32-bit engine sits in FAF's own bin folder, next to ForgedAlliance.exe, which it leaves alone.
		s.arch, s.exeName, s.assetSuffix, s.installDir = "x86", "main.exe", "-x86.zip", filepath.Join(faf, "bin")
	}
	if o.dir != "" {
		if s.installDir, err = filepath.Abs(o.dir); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func platformChecks(s *system) []check {
	// The engine reads FAF's init file and data relative to FAF's folder: bin_x64 must sit next to bin.
	if !strings.EqualFold(filepath.Dir(s.installDir), s.fafData) {
		return []check{{name: "Install folder place", warn: true,
			detail: s.installDir + " is not inside " + s.fafData + "; the engine won't find FAF's files from there",
			fix:    []string{"Leave out --dir to install where the FAF client's files are."}}}
	}
	return nil
}

func writeHint(s *system) []string {
	return []string{"Run setup as administrator, or give your user write access to " + s.fafData + "."}
}

func steamRoots() []string {
	var roots []string
	for _, k := range []struct {
		root  registry.Key
		path  string
		value string
	}{
		{registry.CURRENT_USER, `Software\Valve\Steam`, "SteamPath"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Valve\Steam`, "InstallPath"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Valve\Steam`, "InstallPath"},
	} {
		key, err := registry.OpenKey(k.root, k.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if v, _, err := key.GetStringValue(k.value); err == nil && v != "" {
			roots = append(roots, filepath.FromSlash(v))
		}
		key.Close()
	}
	return append(roots, `C:\Program Files (x86)\Steam`)
}

func freeBytes(dir string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, nil, nil); err != nil {
		return 0, err
	}
	return free, nil
}

// engineRunning reports whether exe is running: Windows refuses to open a running exe for writing.
func engineRunning(exe string) (bool, error) {
	f, err := os.OpenFile(exe, os.O_RDWR, 0)
	if err == nil {
		f.Close()
		return false, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return true, nil
	}
	return false, err
}

func launchArgs(s *system) string {
	log := filepath.Join(s.fafData, "logs", strings.TrimSuffix(s.exeName, ".exe")+".log")
	return `/init init_faf.lua /nobugreport /log "` + log + `"`
}

// createShortcuts adds a shortcut on the desktop and in the Start menu, through PowerShell's
// WScript.Shell (Go has no .lnk writer); the values travel in the environment, so nothing needs quoting.
func createShortcuts(s *system) ([]string, error) {
	os.MkdirAll(filepath.Join(s.fafData, "logs"), 0o755)
	name := "Forged Alliance (faf-re).lnk"
	if s.arch == "x86" {
		name = "Forged Alliance (faf-re x86).lnk"
	}
	const script = `$ErrorActionPreference = 'Stop'
$ws = New-Object -ComObject WScript.Shell
foreach ($dir in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
  if (-not $dir) { continue }
  $p = Join-Path $dir $env:FAFRE_LNK
  $l = $ws.CreateShortcut($p)
  $l.TargetPath = $env:FAFRE_TARGET
  $l.Arguments = $env:FAFRE_ARGS
  $l.WorkingDirectory = $env:FAFRE_DIR
  $l.IconLocation = $env:FAFRE_TARGET + ',0'
  $l.Description = 'The rebuilt Forged Alliance engine'
  $l.Save()
  Write-Output $p
}`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = append(os.Environ(),
		"FAFRE_LNK="+name,
		"FAFRE_TARGET="+filepath.Join(s.installDir, s.exeName),
		"FAFRE_ARGS="+launchArgs(s),
		"FAFRE_DIR="+s.installDir)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}
	var links []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			links = append(links, l)
		}
	}
	return links, nil
}

func afterInstall(s *system) {
	fmt.Println("Start it with the \"Forged Alliance (faf-re)\" shortcut, or from that folder with:")
	fmt.Printf("  %s %s\n", s.exeName, launchArgs(s))
	fmt.Println("If the game crashes, it writes faf_crash_<date>.txt next to the exe; please attach it, with the")
	fmt.Println("log, to an issue at https://github.com/Draiget/scfa-re/issues.")
}

// pauseIfOwnConsole waits for Enter when setup was started by a double click, so its window doesn't
// close before it can be read: then setup is the only process on its console.
func pauseIfOwnConsole() {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	var ids [4]uint32
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	if n == 1 {
		fmt.Print("\nPress Enter to close this window.")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
