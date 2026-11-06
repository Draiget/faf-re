// `desync-diff serve`: receives the desync dumps the engine uploads (telemetry_DumpEndpoint), keeps
// them per game, compares them once two armies' dumps are in, and serves them back.
//
// Each upload is one POST whose body is a .tar.gz and whose X-FAF-Dump header names it
// (desync_<game id>_<beat tag>_army<A>.tar.gz). It is checked as a dump (header.json in the
// archive), stored as <out>/<game id>/<name>, and answered 201. Once a game has dumps from two
// armies, they are compared and the report goes to <out>/<game id>/report.txt.
//
// Reading: GET <prefix>/ lists the games, <prefix>/<game id>/ a game's files, and
// <prefix>/<game id>/<file> downloads one (a dump or report.txt). With --read-token set, a read
// needs "Authorization: Bearer <read token>" or "?token=<read token>"; the upload token (which
// ships with the game) never reads. GET /healthz answers "ok" without a token.
//
// --token and --read-token default to the FAF_UPLOAD_TOKEN and FAF_READ_TOKEN environment
// variables. Plain HTTP: put TLS in front (tools/desync-server).
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	dumpName = regexp.MustCompile(`^desync_([A-Za-z0-9_.-]+?)_(beat\d+|at\d+)_army(-?\d+)\.tar\.gz$`)
	gameName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// maxUnpackedMB caps what one dump may unpack to: a compare holds two dumps in memory, and the
// pod has 512 MB. Real dumps unpack to a few MB.
const maxUnpackedMB = 128

type options struct {
	host, prefix, out, token, readToken string
	port, maxMB                         int
}

type server struct {
	options
	compareLock sync.Mutex
}

func runServe(args []string) int {
	var o options
	flags := flag.NewFlagSet("desync-diff serve", flag.ContinueOnError)
	flags.StringVar(&o.host, "host", "127.0.0.1", "address to listen on")
	flags.IntVar(&o.port, "port", 4319, "port")
	flags.StringVar(&o.prefix, "prefix", "/dumps", "path the dumps are read under")
	flags.StringVar(&o.out, "out", "received-dumps", "storage folder")
	flags.StringVar(&o.token, "token", os.Getenv("FAF_UPLOAD_TOKEN"), "upload token (default $FAF_UPLOAD_TOKEN)")
	flags.StringVar(&o.readToken, "read-token", os.Getenv("FAF_READ_TOKEN"), "read token (default $FAF_READ_TOKEN)")
	flags.IntVar(&o.maxMB, "max-mb", 64, "largest body accepted, in MB")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	o.prefix = "/" + strings.Trim(o.prefix, "/")
	log.SetFlags(0)
	s := &server{options: o}
	address := net.JoinHostPort(o.host, strconv.Itoa(o.port))
	httpServer := &http.Server{
		Addr:              address,
		Handler:           s,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	out, _ := filepath.Abs(o.out)
	log.Printf("receiving dumps on http://%s:%d%s, storing under %s", o.host, o.port, o.prefix, out)
	log.Print(httpServer.ListenAndServe())
	return 1
}

// checkDump reads header.json from an uploaded .tar.gz and checks it is a dump of a known
// format whose files unpack to at most maxUnpackedMB.
func checkDump(data []byte) (map[string]any, error) {
	fail := func(err error) (map[string]any, error) { return nil, fmt.Errorf("not a desync dump: %v", err) }
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fail(err)
	}
	reader := tar.NewReader(gz)
	var raw []byte
	var unpacked int64
	for {
		member, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
		unpacked += member.Size
		if unpacked > maxUnpackedMB<<20 {
			return fail(fmt.Errorf("unpacks to more than %d MB", maxUnpackedMB))
		}
		if member.Name == "header.json" {
			if raw, err = io.ReadAll(reader); err != nil {
				return fail(err)
			}
		}
	}
	if raw == nil {
		return fail(errors.New("no header.json in the archive"))
	}
	value, err := decodeJSON(raw)
	if err != nil {
		return fail(err)
	}
	header, ok := value.(map[string]any)
	if !ok {
		return fail(errors.New("header.json is not an object"))
	}
	if format := header["format"]; !pyEqual(format, json.Number("1")) {
		return nil, fmt.Errorf("unknown dump format %s", pyReprValue(format))
	}
	return header, nil
}

// compareGame writes <folder>/report.txt once the folder has dumps from two armies or more.
func compareGame(folder string) (string, int, bool) {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return "", 0, false
	}
	var dumps []string
	armies := map[string]bool{}
	for _, entry := range entries {
		if m := dumpName.FindStringSubmatch(entry.Name()); m != nil {
			dumps = append(dumps, filepath.Join(folder, entry.Name()))
			armies[m[3]] = true
		}
	}
	if len(armies) < 2 {
		return "", 0, false
	}
	sort.Strings(dumps)
	text, code := compareDumps(dumps, readLimited, 10, 20, false)
	report := filepath.Join(folder, "report.txt")
	if err := writeReplace(report, []byte(text)); err != nil {
		log.Printf("writing %s: %v", report, err)
	}
	return report, code, true
}

// readLimited reads a stored dump, refusing one that unpacks to more than maxUnpackedMB.
func readLimited(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".tar.gz") {
		if _, err := checkDump(data); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func writeReplace(path string, data []byte) error {
	if err := os.WriteFile(path+".tmp", data, 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.upload(w, r)
	case http.MethodGet:
		s.read(w, r)
	default:
		reply(w, http.StatusNotImplemented, "unsupported method "+pyRepr(r.Method))
	}
}

func (s *server) upload(w http.ResponseWriter, r *http.Request) {
	if s.token != "" && r.Header.Get("Authorization") != "Bearer "+s.token {
		reply(w, http.StatusUnauthorized, "bad token")
		return
	}
	name := r.Header.Get("X-FAF-Dump")
	match := dumpName.FindStringSubmatch(name)
	if match == nil {
		reply(w, http.StatusBadRequest, "X-FAF-Dump is not a dump name: "+pyRepr(name))
		return
	}
	length := max(r.ContentLength, 0)
	if length <= 0 || length > int64(s.maxMB)<<20 {
		reply(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("body of %d bytes", length))
		return
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r.Body, data); err != nil {
		reply(w, http.StatusBadRequest, fmt.Sprintf("body shorter than %d bytes: %v", length, err))
		return
	}
	header, err := checkDump(data)
	if err != nil {
		reply(w, http.StatusBadRequest, err.Error())
		return
	}
	game := match[1]
	folder := filepath.Join(s.out, game)
	path := filepath.Join(folder, name)
	if err := os.MkdirAll(folder, 0o755); err == nil {
		err = writeReplace(path, data)
	}
	if err != nil {
		reply(w, http.StatusInternalServerError, "storing failed")
		log.Printf("storing %s: %v", path, err)
		return
	}
	build, _ := header["build"].(map[string]any)
	log.Printf("stored %s (%d bytes, build %s, local army %s)", path, len(data), pyStr(build["commit"]), pyStr(header["local_army"]))
	s.compareLock.Lock()
	report, code, compared := compareGame(folder)
	s.compareLock.Unlock()
	if compared {
		log.Printf("compared %s: exit %d (0 same, 1 differ, 2 invalid input)", report, code)
	}
	body := fmt.Sprintf(`{"stored": %s, "url": %s}`, pyJSONString(name), pyJSONString(s.prefix+"/"+game+"/"+name))
	replyKind(w, http.StatusCreated, body, "application/json")
}

func (s *server) read(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	if path == "/healthz" {
		reply(w, http.StatusOK, "ok")
		return
	}
	token := r.URL.Query().Get("token")
	if s.readToken != "" && r.Header.Get("Authorization") != "Bearer "+s.readToken && token != s.readToken {
		reply(w, http.StatusUnauthorized, "bad read token")
		return
	}
	prefix := strings.TrimRight(s.prefix, "/")
	if !(path == prefix || strings.HasPrefix(path, prefix+"/")) {
		reply(w, http.StatusNotFound, "not found")
		return
	}
	var parts []string
	for _, part := range strings.Split(path[len(prefix):], "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	suffix := ""
	if token != "" {
		suffix = "?token=" + pyQuote(token)
	}
	if len(parts) == 0 {
		var games []string
		if entries, err := os.ReadDir(s.out); err == nil {
			for _, entry := range entries {
				if entry.IsDir() && gameName.MatchString(entry.Name()) {
					games = append(games, entry.Name())
				}
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(games)))
		var rows strings.Builder
		for _, game := range games {
			entries, _ := os.ReadDir(filepath.Join(s.out, game))
			dumps, report := 0, false
			for _, entry := range entries {
				if dumpName.MatchString(entry.Name()) {
					dumps++
				}
				report = report || entry.Name() == "report.txt"
			}
			link := ""
			if report {
				link = fmt.Sprintf(`, <a href="%s/%s/report.txt%s">report</a>`, prefix, game, suffix)
			}
			fmt.Fprintf(&rows, `<li><a href="%s/%s/%s">%s</a>: %d dump(s)%s</li>`, prefix, game, suffix, html.EscapeString(game), dumps, link)
		}
		content := "<p>No dumps yet.</p>"
		if rows.Len() > 0 {
			content = "<ul>" + rows.String() + "</ul>"
		}
		page(w, "Desync dumps", content)
		return
	}
	game := parts[0]
	folder := filepath.Join(s.out, game)
	if info, err := os.Stat(folder); !gameName.MatchString(game) || err != nil || !info.IsDir() || len(parts) > 2 {
		reply(w, http.StatusNotFound, "not found")
		return
	}
	if len(parts) == 1 {
		entries, _ := os.ReadDir(folder)
		var names []string
		for _, entry := range entries {
			if dumpName.MatchString(entry.Name()) || entry.Name() == "report.txt" {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)
		var rows strings.Builder
		for _, name := range names {
			var size int64
			if info, err := os.Stat(filepath.Join(folder, name)); err == nil {
				size = info.Size()
			}
			fmt.Fprintf(&rows, `<li><a href="%s/%s/%s%s">%s</a> (%d bytes)</li>`, prefix, game, name, suffix, html.EscapeString(name), size)
		}
		page(w, "Game "+game, "<ul>"+rows.String()+"</ul>")
		return
	}
	name := parts[1]
	file := filepath.Join(folder, name)
	info, err := os.Stat(file)
	if !(dumpName.MatchString(name) || name == "report.txt") || err != nil || !info.Mode().IsRegular() {
		reply(w, http.StatusNotFound, "not found")
		return
	}
	body, err := os.ReadFile(file)
	if err != nil {
		reply(w, http.StatusNotFound, "not found")
		return
	}
	kind := "application/gzip"
	if name == "report.txt" {
		kind = "text/plain; charset=utf-8"
	} else {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	}
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func page(w http.ResponseWriter, title, content string) {
	t := html.EscapeString(title)
	replyKind(w, http.StatusOK, "<!doctype html><meta charset=utf-8><title>"+t+"</title><h1>"+t+"</h1>"+content, "text/html; charset=utf-8")
}

func reply(w http.ResponseWriter, code int, text string) {
	replyKind(w, code, text, "text/plain; charset=utf-8")
}

func replyKind(w http.ResponseWriter, code int, text, kind string) {
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Content-Length", strconv.Itoa(len(text)))
	w.WriteHeader(code)
	io.WriteString(w, text)
	if code >= 400 {
		log.Printf("refused %d: %s", code, text)
	}
}
