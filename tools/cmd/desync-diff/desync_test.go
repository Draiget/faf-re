package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDump packs a small dump of game 424242 for army `army`; `health` is the value army 1 nudges.
func fakeDump(t *testing.T, army int, health string) []byte {
	t.Helper()
	header := fmt.Sprintf(`{"format": 1, "build": {"identity": "test x64", "commit": "abc", "arch": "x64", "dirty": false},
"game": {"faf_game_id": "424242", "map": "/maps/a/a.scmap", "replay": false},
"command_sources": [{"index": 0, "name": "A"}, {"index": 1, "name": "B"}],
"armies": [{"index": 0, "player": "A", "army": "ARMY_1"}, {"index": 1, "player": "B", "army": "ARMY_2"}],
"local_army": %d, "desync": {"dump_beat": 301, "first_mismatched_beat": 300},
"settings": {"switches": "sim_X=1"}}`, army)
	files := map[string]string{
		"header.json":         header,
		"hashes.csv":          "beat,source,name,reported,ours,match\n250,0,A,aaaa,aaaa,1\n250,1,B,aaaa,aaaa,1\n300,0,A,bbbb,bbbb,1\n300,1,B,cccc,bbbb,0\n",
		"beats/beat00300.log": "Dirty Entities\n  0x00000000\n    health: " + health + "\n    bp:uel0001\n",
		"state.txt":           "beat 301\nEntities\n0x00000000 bp=uel0001 army=0 health=" + health + "\n",
	}
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"header.json", "hashes.csv", "beats/beat00300.log", "state.txt"} {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		io.WriteString(tw, body)
	}
	tw.Close()
	gz.Close()
	return data.Bytes()
}

func request(t *testing.T, s *server, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestUploadCompareAndRead(t *testing.T) {
	out := t.TempDir()
	s := &server{options: options{prefix: "/dumps", out: out, token: "up", readToken: "rd", maxMB: 64}}
	upload := func(name string, body []byte, token string) *httptest.ResponseRecorder {
		return request(t, s, "POST", "/dumps", body, map[string]string{"Authorization": "Bearer " + token, "X-FAF-Dump": name})
	}
	a := fakeDump(t, 0, "12000.0 0x463b8000")
	b := fakeDump(t, 1, "12000.0 0x463b8001")

	if rec := upload("desync_424242_beat300_army0.tar.gz", a, "wrong"); rec.Code != 401 {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := upload("../evil.tar.gz", a, "up"); rec.Code != 400 {
		t.Fatalf("bad name: %d", rec.Code)
	}
	if rec := upload("desync_424242_beat300_army0.tar.gz", []byte("not gzip"), "up"); rec.Code != 400 {
		t.Fatalf("bad body: %d %s", rec.Code, rec.Body)
	}
	if rec := upload("desync_424242_beat300_army0.tar.gz", nil, "up"); rec.Code != 413 {
		t.Fatalf("empty body: %d", rec.Code)
	}
	rec := upload("desync_424242_beat300_army0.tar.gz", a, "up")
	if rec.Code != 201 || rec.Body.String() != `{"stored": "desync_424242_beat300_army0.tar.gz", "url": "/dumps/424242/desync_424242_beat300_army0.tar.gz"}` {
		t.Fatalf("upload A: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(out, "424242", "report.txt")); err == nil {
		t.Fatal("report written with one army")
	}
	if rec := upload("desync_424242_beat300_army1.tar.gz", b, "up"); rec.Code != 201 {
		t.Fatalf("upload B: %d %s", rec.Code, rec.Body)
	}
	report, err := os.ReadFile(filepath.Join(out, "424242", "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"first beat with differing hashes: 300 (the two differ)",
		"about: entity 0x00000000 bp=uel0001 army 0 A [ARMY_1]",
		"field: health",
		"Result: the dumps differ",
	} {
		if !strings.Contains(string(report), want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}

	if rec := request(t, s, "GET", "/healthz", nil, nil); rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("healthz: %d", rec.Code)
	}
	if rec := request(t, s, "GET", "/dumps/", nil, map[string]string{"Authorization": "Bearer up"}); rec.Code != 401 {
		t.Fatalf("upload token reads: %d", rec.Code)
	}
	rec = request(t, s, "GET", "/dumps/?token=rd", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `<a href="/dumps/424242/?token=rd">424242</a>: 2 dump(s), <a href="/dumps/424242/report.txt?token=rd">report</a>`) {
		t.Fatalf("games list: %d %s", rec.Code, rec.Body)
	}
	rec = request(t, s, "GET", "/dumps/424242/", nil, map[string]string{"Authorization": "Bearer rd"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "desync_424242_beat300_army1.tar.gz</a> (") {
		t.Fatalf("game page: %d %s", rec.Code, rec.Body)
	}
	rec = request(t, s, "GET", "/dumps/424242/desync_424242_beat300_army0.tar.gz", nil, map[string]string{"Authorization": "Bearer rd"})
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), a) || rec.Header().Get("Content-Disposition") == "" {
		t.Fatalf("download: %d", rec.Code)
	}
	for _, target := range []string{"/dumps/424242/x.txt", "/dumps/..%2f/report.txt", "/dumps/424242/report.txt/x", "/other"} {
		if rec := request(t, s, "GET", target+"?token=rd", nil, nil); rec.Code != 404 {
			t.Errorf("%s: %d", target, rec.Code)
		}
	}
}

func TestCompareSameDumpExitsZero(t *testing.T) {
	a := fakeDump(t, 0, "1.0 0x3f800000")
	read := func(string) ([]byte, error) { return a, nil }
	text, code := compareDumps([]string{"a.tar.gz", "b.tar.gz"}, read, 10, 20, false)
	if code != 0 || !strings.HasSuffix(text, "Result: no difference between the dumps\n") {
		t.Fatalf("exit %d:\n%s", code, text)
	}
}

func TestPythonText(t *testing.T) {
	cases := map[string]string{
		pyRepr("a'b"):        `"a'b"`,
		pyRepr("a'b\"c"):     `'a\'b"c'`,
		pyRepr("Æ\x01"):      `'Æ\x01'`,
		pyJSONString("é\"😀"): `"\u00e9\"\ud83d\ude00"`,
		strings.Join(splitLines("a\r\nb\rc\n\nd\n"), "|"): "a|b|c||d",
		pyQuote("a b/ü"):                 "a%20b/%C3%BC",
		compact([]int{1, 2, 3, 5, 7, 8}): "1-3, 5, 7-8",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}
