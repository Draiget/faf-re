package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestReadLuaString(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fa_path.lua")
	text := "-- comment\nfa_path = \"C:\\\\Games\\\\Forged \\\"FA\\\"\"\ncustom_vault_path = 'D:/vault'\nGameVersion = \"3840\"\n"
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"fa_path": `C:\Games\Forged "FA"`, "custom_vault_path": "D:/vault", "GameVersion": "3840"} {
		got, err := readLuaString(p, key)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", key, got, err, want)
		}
	}
	if _, err := readLuaString(p, "missing"); err == nil {
		t.Error("missing key: want an error")
	}
}

func TestSteamLibraries(t *testing.T) {
	vdf := `"libraryfolders"
{
	"0"
	{
		"path"		"C:\\Program Files (x86)\\Steam"
		"label"		""
	}
	"1"
	{
		"path"		"G:\\games"
		"apps" { "9420" "123" }
	}
}`
	got := steamLibraries(vdf)
	want := []string{`C:\Program Files (x86)\Steam`, `G:\games`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseSums(t *testing.T) {
	a, b := strings.Repeat("ab", 32), strings.Repeat("CD", 32)
	got := parseSums(a + "  faf-engine-1-x64.zip\n" + b + " *main.exe\r\nnot a line\n" + "zz  short\n")
	want := map[string]string{"faf-engine-1-x64.zip": a, "main.exe": strings.ToLower(b)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTagFromName(t *testing.T) {
	for _, c := range []struct {
		name, suffix, tag string
		ok                bool
	}{
		{"faf-engine-2026.11.015-x64.zip", "-x64.zip", "2026.11.015", true},
		{"faf-engine-2026.11.013-nightly-linux-x64.tar.gz", "-linux-x64.tar.gz", "2026.11.013-nightly", true},
		{"faf-engine-2026.11.015-x86.zip", "-x64.zip", "", false},
		{"other.zip", "-x64.zip", "", false},
	} {
		tag, ok := tagFromName(c.name, c.suffix)
		if tag != c.tag || ok != c.ok {
			t.Errorf("%s: got %q %v, want %q %v", c.name, tag, ok, c.tag, c.ok)
		}
	}
}

func TestGlibcCheck(t *testing.T) {
	for _, c := range []struct {
		out, version  string
		ok, newEnough bool
	}{
		{"ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39\nCopyright ...", "2.39", true, true},
		{"ldd (Debian GLIBC 2.31-13+deb11u5) 2.31\n", "2.31", true, false},
		{"ldd (GNU libc) 2.34\n", "2.34", true, true},
		{"ldd (GNU libc) 2.4\n", "2.4", true, false},
		{"musl libc (x86_64)\nVersion 1.2.4\n", "", false, false},
		{"", "", false, false},
	} {
		v, err := parseLddVersion(c.out)
		if (err == nil) != c.ok || v != c.version {
			t.Errorf("%q: got %q, %v", c.out, v, err)
		}
		if err == nil && glibcAtLeast(v, 2, 34) != c.newEnough {
			t.Errorf("%q: glibcAtLeast(2.34) = %v", v, !c.newEnough)
		}
	}
}

func TestCleanEntry(t *testing.T) {
	good := map[string]string{"./": "", "./a/b.lua": "a/b.lua", `fafengine\lua\x.lua`: "fafengine/lua/x.lua", "dir/": "dir"}
	for in, want := range good {
		if got, err := cleanEntry(in); err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"../x", "a/../../x", "/etc/passwd", `C:\Windows\x`, `..\x`} {
		if _, err := cleanEntry(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

type entry struct {
	name string
	body string
	exec bool
	dir  bool
	link bool
}

func makeZip(t *testing.T, path string, entries []entry) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		if e.dir {
			if _, err := w.Create(e.name); err != nil {
				t.Fatal(err)
			}
			continue
		}
		f, err := w.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(e.body))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func makeTarGz(t *testing.T, path string, entries []entry) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(e.body))}
		switch {
		case e.dir:
			h.Typeflag, h.Mode, h.Size = tar.TypeDir, 0o755, 0
		case e.link:
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, "/etc/passwd", 0
		case e.exec:
			h.Mode = 0o755
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readAll(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			rel, _ := filepath.Rel(root, p)
			data, _ := os.ReadFile(p)
			out[filepath.ToSlash(rel)] = string(data)
		}
		return nil
	})
	return out
}

func TestExtractZip(t *testing.T) {
	dir := t.TempDir()
	z := filepath.Join(dir, "p.zip")
	makeZip(t, z, []entry{{name: "fafengine/lua/", dir: true}, {name: "fafengine/lua/a.lua", body: "A"}, {name: `fafengine\b.fx`, body: "B"}, {name: "main_x64.exe", body: "EXE"}})
	dest := filepath.Join(dir, "out")
	files, err := extractZip(z, dest)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"fafengine/b.fx", "fafengine/lua/a.lua", "main_x64.exe"}; !reflect.DeepEqual(files, want) {
		t.Errorf("files %q, want %q", files, want)
	}
	if got := readAll(t, dest); got["fafengine/b.fx"] != "B" || got["main_x64.exe"] != "EXE" {
		t.Errorf("contents %v", got)
	}

	evil := filepath.Join(dir, "evil.zip")
	makeZip(t, evil, []entry{{name: "../escaped.txt", body: "x"}})
	if _, err := extractZip(evil, filepath.Join(dir, "out2")); err == nil {
		t.Error("an entry leaving the folder was unpacked")
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped.txt")); err == nil {
		t.Error("escaped.txt was written outside the folder")
	}
}

func TestExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.tar.gz")
	makeTarGz(t, p, []entry{{name: "./", dir: true}, {name: "./ForgedAlliance", body: "ELF", exec: true}, {name: "./fafengine/", dir: true}, {name: "./fafengine/x.lua", body: "X"}})
	dest := filepath.Join(dir, "out")
	files, err := extractTarGz(p, dest)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ForgedAlliance", "fafengine/x.lua"}; !reflect.DeepEqual(files, want) {
		t.Errorf("files %q, want %q", files, want)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(dest, "ForgedAlliance"))
		if st.Mode().Perm()&0o111 == 0 {
			t.Errorf("ForgedAlliance lost its exec bits: %v", st.Mode())
		}
	}
	for _, bad := range [][]entry{{{name: "./link", link: true}}, {{name: "../../x", body: "x"}}} {
		q := filepath.Join(dir, "bad.tar.gz")
		makeTarGz(t, q, bad)
		if _, err := extractTarGz(q, filepath.Join(dir, "bad")); err == nil {
			t.Errorf("%q was unpacked", bad[0].name)
		}
	}
}

func TestSwapInRollsBack(t *testing.T) {
	dir := t.TempDir()
	stage, backup := filepath.Join(dir, stageName), filepath.Join(dir, backupName)
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("old a"), 0o644)
	os.MkdirAll(stage, 0o755)
	os.WriteFile(filepath.Join(stage, "a.txt"), []byte("new a"), 0o644)
	// b.txt is listed but not staged, so its move fails after a.txt went in.
	_, err := swapIn(dir, stage, backup, []string{"a.txt", "b.txt"})
	if err == nil {
		t.Fatal("want an error")
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(data) != "old a" {
		t.Errorf("a.txt is %q after the rollback, want the old file", data)
	}
}

// fakeSystem installs into a temporary folder with no shortcuts.
func fakeSystem(t *testing.T, suffix, exe string) *system {
	return &system{goos: runtime.GOOS, arch: "x64", fafData: t.TempDir(), installDir: filepath.Join(t.TempDir(), "bin_x64"),
		exeName: exe, assetSuffix: suffix}
}

func writeSums(t *testing.T, dir string, files ...string) {
	var b strings.Builder
	for _, f := range files {
		data, _ := os.ReadFile(filepath.Join(dir, f))
		sum := sha256.Sum256(data)
		b.WriteString(hex.EncodeToString(sum[:]) + "  " + f + "\n")
	}
	os.WriteFile(filepath.Join(dir, sumsName), []byte(b.String()), 0o644)
}

func TestInstallUpdateUninstall(t *testing.T) {
	s := fakeSystem(t, "-x64.zip", "main_x64.exe")
	o := options{noShortcut: true, yes: true}
	src := t.TempDir()

	v1 := filepath.Join(src, "faf-engine-1.0-x64.zip")
	makeZip(t, v1, []entry{{name: "main_x64.exe", body: "v1"}, {name: "fafengine/old.lua", body: "old"}, {name: "fafengine/keep.lua", body: "k1"}})
	writeSums(t, src, filepath.Base(v1))
	p, err := localPackage(s, v1)
	if err != nil {
		t.Fatal(err)
	}
	if err := install(s, o, p); err != nil {
		t.Fatal(err)
	}
	// A file of the player's own in the folder is never touched.
	os.WriteFile(filepath.Join(s.installDir, "mine.txt"), []byte("mine"), 0o644)

	v2 := filepath.Join(src, "faf-engine-2.0-x64.zip")
	makeZip(t, v2, []entry{{name: "main_x64.exe", body: "v2"}, {name: "fafengine/keep.lua", body: "k2"}})
	writeSums(t, src, filepath.Base(v1), filepath.Base(v2))
	if p, err = localPackage(s, v2); err != nil {
		t.Fatal(err)
	}
	if err := install(s, o, p); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, s.installDir)
	m, _ := readManifest(s.installDir)
	if m == nil || m.Version != "2.0" {
		t.Fatalf("manifest %+v", m)
	}
	delete(got, manifestName)
	want := map[string]string{"main_x64.exe": "v2", "fafengine/keep.lua": "k2", "mine.txt": "mine"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("after the update: %v, want %v", got, want)
	}

	if err := uninstall(s, o); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, s.installDir); !reflect.DeepEqual(got, map[string]string{"mine.txt": "mine"}) {
		t.Errorf("after uninstall: %v", got)
	}
}

// Installing into a folder that already has files of the same names (FAF's bin for --x86, or a hand
// install) keeps those originals through updates, and --uninstall puts them back.
func TestOriginalsKeptAndRestored(t *testing.T) {
	s := fakeSystem(t, "-x86.zip", "main.exe")
	o := options{noShortcut: true, yes: true}
	os.MkdirAll(filepath.Join(s.installDir, "fafengine"), 0o755)
	os.WriteFile(filepath.Join(s.installDir, "main.exe"), []byte("original main"), 0o644)
	os.WriteFile(filepath.Join(s.installDir, "fafengine", "x.lua"), []byte("original x"), 0o644)
	os.WriteFile(filepath.Join(s.installDir, "ForgedAlliance.exe"), []byte("FAF"), 0o644)
	before := readAll(t, s.installDir)

	src := t.TempDir()
	for i, body := range []string{"v1", "v2"} {
		pkg := filepath.Join(src, "faf-engine-"+body+"-x86.zip")
		makeZip(t, pkg, []entry{{name: "main.exe", body: body}, {name: "fafengine/x.lua", body: body}, {name: "dxil.dll", body: body}})
		os.Remove(filepath.Join(src, sumsName))
		p, err := localPackage(s, pkg)
		if err != nil {
			t.Fatal(err)
		}
		if err := install(s, o, p); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
	}
	m, _ := readManifest(s.installDir)
	if want := []string{"fafengine/x.lua", "main.exe"}; m == nil || !reflect.DeepEqual(m.Originals, want) {
		t.Fatalf("originals %+v, want %q", m, want)
	}
	if data, _ := os.ReadFile(filepath.Join(s.installDir, "main.exe")); string(data) != "v2" {
		t.Errorf("main.exe is %q, want v2", data)
	}
	if err := uninstall(s, o); err != nil {
		t.Fatal(err)
	}
	if after := readAll(t, s.installDir); !reflect.DeepEqual(after, before) {
		t.Errorf("after uninstall: %v, want the folder as it was: %v", after, before)
	}
}

func TestInstallRefusesBadChecksum(t *testing.T) {
	s := fakeSystem(t, "-x64.zip", "main_x64.exe")
	src := t.TempDir()
	pkg := filepath.Join(src, "faf-engine-1.0-x64.zip")
	makeZip(t, pkg, []entry{{name: "main_x64.exe", body: "v1"}})
	os.WriteFile(filepath.Join(src, sumsName), []byte(strings.Repeat("0", 64)+"  faf-engine-1.0-x64.zip\n"), 0o644)
	p, err := localPackage(s, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := install(s, options{noShortcut: true, yes: true}, p); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("got %v, want a checksum error", err)
	}
	if _, err := os.Stat(filepath.Join(s.installDir, "main_x64.exe")); err == nil {
		t.Error("the engine was installed from a package that failed its checksum")
	}
}

func TestResolveAndDownload(t *testing.T) {
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	f, _ := zw.Create("main_x64.exe")
	f.Write([]byte("engine"))
	zw.Close()
	body := zipBuf.Bytes()
	sum := sha256.Sum256(body)
	good := hex.EncodeToString(sum[:])
	sums := good + "  faf-engine-9.9-x64.zip\n"

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rel := release{Tag: "9.9", Assets: []asset{
		{Name: "faf-engine-9.9-x64.zip", URL: srv.URL + "/dl/pkg", Size: int64(len(body))},
		{Name: sumsName, URL: srv.URL + "/dl/sums"},
	}}
	mux.HandleFunc("/repo/releases/latest", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(rel) })
	mux.HandleFunc("/dl/pkg", func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	mux.HandleFunc("/dl/sums", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sums)) })
	old := apiBase
	apiBase = srv.URL + "/repo"
	defer func() { apiBase = old }()

	s := fakeSystem(t, "-x64.zip", "main_x64.exe")
	p, err := resolvePackage(s, options{})
	if err != nil {
		t.Fatal(err)
	}
	if p.tag != "9.9" || p.sha256 != good {
		t.Fatalf("package %+v", p)
	}
	if err := install(s, options{noShortcut: true, yes: true}, p); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(s.installDir, "main_x64.exe")); string(data) != "engine" {
		t.Errorf("installed %q", data)
	}
	// No leftovers from the download or the staging.
	entries, _ := os.ReadDir(s.installDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".faf-re-setup") {
			t.Errorf("leftover %s", e.Name())
		}
	}

	// A tag the release doesn't have a package for, and a tampered download.
	if _, err := resolvePackage(fakeSystem(t, "-x86.zip", "main.exe"), options{}); err == nil {
		t.Error("x86: want an error, the release has no x86 package")
	}
	sums = strings.Repeat("1", 64) + "  faf-engine-9.9-x64.zip\n"
	if p, err = resolvePackage(s, options{}); err != nil {
		t.Fatal(err)
	}
	if err := install(fakeSystem(t, "-x64.zip", "main_x64.exe"), options{noShortcut: true, yes: true}, p); err == nil {
		t.Error("a download that doesn't match the checksum was installed")
	}
}
