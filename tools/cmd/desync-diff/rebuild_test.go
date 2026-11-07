package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as the engine for rebuild: with FAKE_ENGINE_DUMP set, the test binary records
// its arguments, writes the recorder's "wrote" line naming that dump into its /log file, and then
// keeps running like a replay that goes on after the dump, until rebuild stops it.
func TestMain(m *testing.M) {
	if dump := os.Getenv("FAKE_ENGINE_DUMP"); dump != "" {
		os.WriteFile(os.Getenv("FAKE_ENGINE_ARGS"), []byte(strings.Join(os.Args[1:], "\n")), 0o644)
		for i, arg := range os.Args {
			if arg == "/log" && i+1 < len(os.Args) {
				os.WriteFile(os.Args[i+1], []byte("Desync recorder: wrote "+dump+" (1 bytes)\n"), 0o644)
			}
		}
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// tarToZip repacks a fakeDump .tar.gz as the .zip the engine writes next to its log.
func tarToZip(t *testing.T, data []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(gz)
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for {
		member, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		w, _ := zw.Create(member.Name)
		io.Copy(w, reader)
	}
	zw.Close()
	return out.Bytes()
}

func TestRebuildRunsTheEngineAndCompares(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "desync_424242_beat300_army0.tar.gz")
	os.WriteFile(base, fakeDump(t, 0, "12000.0 0x463b8000"), 0o644)
	rebuilt := filepath.Join(dir, "rebuilt-side.zip")
	os.WriteFile(rebuilt, tarToZip(t, fakeDump(t, 1, "12000.0 0x463b8001")), 0o644)
	argsFile := filepath.Join(dir, "args.txt")
	t.Setenv("FAKE_ENGINE_DUMP", rebuilt)
	t.Setenv("FAKE_ENGINE_ARGS", argsFile)

	out := filepath.Join(dir, "run")
	r := &report{}
	start := time.Now()
	code, err := rebuild(r, base, os.Args[0], "game.scfareplay", "init.lua", out, time.Minute, false,
		[]string{"/simworkers", "8"}, 10, 20, false)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("rebuild waited %v: the engine was not stopped once the dump was written", elapsed)
	}
	if code != 1 || !strings.Contains(r.String(), "wrote: "+rebuilt) || !strings.Contains(r.String(), "field: health") {
		t.Fatalf("exit %d:\n%s", code, r.String())
	}
	args, _ := os.ReadFile(argsFile)
	want := strings.Join([]string{"--replay", "game.scfareplay", "/init", "init.lua", "/nosound", "/log",
		filepath.Join(out, "game.log"), "/desyncrecorder", "/desyncdumpbeat", "301", "/simworkers", "8"}, "\n")
	if string(args) != want {
		t.Errorf("engine arguments:\n%s\nwant:\n%s", args, want)
	}
}

func TestListToCmdline(t *testing.T) {
	got := listToCmdline([]string{`C:\a b\x.exe`, "", `q"uote`, `tail\`, `dir\ space\`, `plain`})
	want := `"C:\a b\x.exe" "" q\"uote tail\ "dir\ space\\" plain`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
