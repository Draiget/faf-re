package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"faf-main/tools/oidcmock"
)

// fakeHost is a server-host as far as the service uses it: host, pool, maps, plan, lobbies (list, create, stop),
// each lobby's status, ops and event stream, and the public request API.
type fakeHost struct {
	t     *testing.T
	token string
	srv   *httptest.Server

	mu          sync.Mutex
	load        float64
	fits        bool
	poolEnabled bool
	poolAccess  string
	echo        string // its RTT echo address, as server-host reports it
	maps        []hostMap
	lobbies     []map[string]any
	status      map[string]map[string]any
	created     []map[string]any
	ops         []string
	requests    []map[string]any
	nextID      int
	subs        map[string][]chan string // lobby id -> event stream subscribers
	statusCalls int
}

func newFakeHost(t *testing.T, load float64) *fakeHost {
	f := &fakeHost{t: t, token: "host-token-" + strconv.Itoa(int(load*10)) + "-0123456789", load: load, fits: true,
		poolAccess: "open", maps: []hostMap{{ID: "scmp_009", Name: "Seton's Clutch", KM: 20, Players: 8}, {ID: "scmp_007", Name: "Open Palms", KM: 10, Players: 6}},
		status: map[string]map[string]any{}, subs: map[string][]chan string{}}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHost) write(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// addLobby puts a lobby on the host as if made elsewhere (e.g. its dashboard).
func (f *fakeHost) addLobby(l map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lobbies = append(f.lobbies, l)
}

func (f *fakeHost) setState(id, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.lobbies {
		if l["id"] == id {
			l["state"] = state
		}
	}
}

func (f *fakeHost) setStatus(id string, st map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id] = st
}

// emit sends an event on a lobby's stream to whoever follows it; false when nobody does yet.
func (f *fakeHost) emit(id, name, data string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.subs[id] {
		c <- "event: " + name + "\ndata: " + data + "\n\n"
	}
	return len(f.subs[id]) > 0
}

func (f *fakeHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/api/v1/public/") {
		f.public(w, r, strings.TrimPrefix(p, "/api/v1/public/"))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.write(w, 401, map[string]any{"ok": false, "error": "missing or wrong admin token"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case p == "/api/v1/host":
		cpus := []map[string]any{}
		for i := 0; i < 4; i++ {
			cpus = append(cpus, map[string]any{"id": i, "load10": f.load})
		}
		running := 0
		for _, l := range f.lobbies {
			if runningState(l["state"].(string)) {
				running++
			}
		}
		f.write(w, 200, map[string]any{"ok": true, "host": map[string]any{"name": "fake", "cpu_model": "Fake CPU",
			"memory_mb": map[string]int{"total": 16000, "available": 12000}, "cpus": cpus, "lobbies": running,
			"nodes": []any{map[string]any{"id": 0}}, "rtt_echo": f.echo}})
	case p == "/api/v1/pool":
		f.write(w, 200, map[string]any{"ok": true, "pool": map[string]any{"enabled": f.poolEnabled, "max_games": 4,
			"access": f.poolAccess, "code": "c0de"}, "usage": map[string]any{"games": 0, "queued": len(f.requests)}})
	case p == "/api/v1/maps":
		f.write(w, 200, map[string]any{"ok": true, "maps": f.maps})
	case p == "/api/v1/plan" && r.Method == http.MethodPost:
		warnings := []any{}
		if !f.fits {
			warnings = append(warnings, map[string]any{"code": "node_short", "severity": "error", "text": "no free cores"})
		}
		f.write(w, 200, map[string]any{"ok": true, "plan": map[string]any{"fits": f.fits, "warnings": warnings}})
	case p == "/api/v1/lobbies" && r.Method == http.MethodGet:
		f.write(w, 200, map[string]any{"ok": true, "lobbies": f.lobbies})
	case p == "/api/v1/lobbies" && r.Method == http.MethodPost:
		var req map[string]any
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		if err := dec.Decode(&req); err != nil {
			f.write(w, 400, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		f.created = append(f.created, req)
		if !f.fits {
			f.write(w, 409, map[string]any{"ok": false, "error": "doesn't fit"})
			return
		}
		f.nextID++
		id := "l" + strconv.Itoa(f.nextID)
		seats := []any{}
		raw, _ := json.Marshal(req["seats"])
		var in []map[string]any
		_ = json.Unmarshal(raw, &in)
		for i, s := range in {
			s["seat"] = i + 1
			if s["kind"] == "human" {
				s["join"] = fmt.Sprintf("/connectserver 203.0.113.5:27200 /servertoken secret%d /serveruid %v", i+1, s["uid"])
			}
			seats = append(seats, s)
		}
		obs := []any{}
		raw, _ = json.Marshal(req["observers"])
		var ins []map[string]any
		_ = json.Unmarshal(raw, &ins)
		for i, o := range ins {
			o["watch"] = fmt.Sprintf("/replay gpgnet://203.0.113.5:27201/watch%d", i+1)
			obs = append(obs, o)
		}
		l := map[string]any{"id": id, "name": req["name"], "state": "lobby", "phase": "lobby", "kind": req["kind"],
			"control": req["control"], "map": map[string]any{"id": req["map"]}, "options": map[string]any{},
			"seats": seats, "observers": obs, "cpus": []int{1}, "usage": map[string]any{"cpu_cores": 0.1}}
		f.lobbies = append(f.lobbies, l)
		f.status[id] = map[string]any{"phase": "lobby", "host": 0, "seats": []any{}}
		f.write(w, 200, map[string]any{"ok": true, "lobby": l})
	case strings.HasPrefix(p, "/api/v1/lobbies/"):
		rest := strings.TrimPrefix(p, "/api/v1/lobbies/")
		id, sub, _ := strings.Cut(rest, "/")
		var lobby map[string]any
		for _, l := range f.lobbies {
			if l["id"] == id {
				lobby = l
			}
		}
		if lobby == nil {
			f.write(w, 404, map[string]any{"ok": false, "error": "no such lobby"})
			return
		}
		switch {
		case sub == "" && r.Method == http.MethodDelete:
			lobby["state"] = "stopped"
			f.write(w, 200, map[string]any{"ok": true, "lobby": lobby})
		case sub == "api/v1/status":
			f.statusCalls++
			f.write(w, 200, f.status[id])
		case sub == "api/v1/armies":
			f.write(w, 200, map[string]any{"ok": true, "armies": []any{}})
		case strings.HasPrefix(sub, "api/v1/ops/"):
			body, _ := io.ReadAll(r.Body)
			f.ops = append(f.ops, strings.TrimPrefix(sub, "api/v1/ops/")+" "+string(body))
			f.write(w, 200, map[string]any{"ok": true})
		case sub == "api/v1/events":
			c := make(chan string, 16)
			f.subs[id] = append(f.subs[id], c)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			defer f.mu.Lock()
			for {
				select {
				case <-r.Context().Done():
					return
				case m := <-c:
					_, _ = io.WriteString(w, m)
					w.(http.Flusher).Flush()
				}
			}
		default:
			f.write(w, 404, map[string]any{"ok": false, "error": "no " + sub})
		}
	default:
		f.write(w, 404, map[string]any{"ok": false, "error": "no " + p})
	}
}

func (f *fakeHost) public(w http.ResponseWriter, r *http.Request, rest string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case rest == "requests" && r.Method == http.MethodPost:
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if !f.poolEnabled {
			f.write(w, 403, map[string]any{"ok": false, "error": "player hosting is off on this host"})
			return
		}
		if f.poolAccess == "code" && req["code"] != "c0de" {
			f.write(w, 403, map[string]any{"ok": false, "error": "wrong access code"})
			return
		}
		f.nextID++
		req["id"], req["key"], req["state"] = "r"+strconv.Itoa(f.nextID), "key"+strconv.Itoa(f.nextID), "queued"
		f.requests = append(f.requests, req)
		f.write(w, 200, map[string]any{"ok": true, "request": req})
	case strings.HasPrefix(rest, "requests/"):
		id := strings.TrimPrefix(rest, "requests/")
		for _, q := range f.requests {
			if q["id"] == id {
				if q["key"] != r.URL.Query().Get("key") {
					break
				}
				if r.Method == http.MethodDelete {
					q["state"] = "cancelled"
				}
				f.write(w, 200, map[string]any{"ok": true, "request": q})
				return
			}
		}
		f.write(w, 404, map[string]any{"ok": false, "error": "no such request"})
	default:
		f.write(w, 404, map[string]any{"ok": false, "error": "no " + rest})
	}
}

// env is a control service with a mock FAF provider and fake hosts.
type env struct {
	t     *testing.T
	idp   *oidcmock.Provider
	ts    *httptest.Server
	s     *server
	store Store
	admin string
	dir   string
}

const (
	uidAdmin     = 1
	uidOrganiser = 2 // global organiser
	uidTO        = 3 // organises tournament "cup" only
	uidPlayerA   = 10
	uidPlayerB   = 11
	uidCaster    = 20
	uidOutsider  = 99
)

type envOpts struct {
	store         Store
	nameInIDToken bool
	secret        string
	extraYAML     string
}

func newEnv(t *testing.T, hosts map[string]*fakeHost, o envOpts) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, dir: dir, admin: "control-admin-token-0123456789"}
	ctl := httptest.NewUnstartedServer(nil)
	ctlURL := "http://" + ctl.Listener.Addr().String()
	idpSrv := httptest.NewUnstartedServer(nil)
	idpURL := "http://" + idpSrv.Listener.Addr().String()
	idp, err := oidcmock.New(idpURL, "faf-control", o.secret, []string{ctlURL + "/auth/callback"},
		oidcmock.User{ID: uidPlayerA, Name: "PlayerA"}, oidcmock.User{ID: uidAdmin, Name: "Admin"},
		oidcmock.User{ID: uidOrganiser, Name: "Org"}, oidcmock.User{ID: uidTO, Name: "CupTO"},
		oidcmock.User{ID: uidPlayerB, Name: "PlayerB"}, oidcmock.User{ID: uidCaster, Name: "Caster"},
		oidcmock.User{ID: uidOutsider, Name: "Outsider"})
	if err != nil {
		t.Fatal(err)
	}
	idp.NameInIDToken = o.nameInIDToken
	e.idp = idp
	idpSrv.Config.Handler = idp
	idpSrv.Start()
	t.Cleanup(idpSrv.Close)

	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "admin.token"), []byte(e.admin+"\n"), 0o600))
	secretLine := ""
	if o.secret != "" {
		must(os.WriteFile(filepath.Join(dir, "oidc.secret"), []byte(o.secret), 0o600))
		secretLine = "  client_secret_file: oidc.secret\n"
	}
	var hostsYAML strings.Builder
	for name, h := range hosts {
		must(os.WriteFile(filepath.Join(dir, name+".token"), []byte(h.token), 0o600))
		fmt.Fprintf(&hostsYAML, "  - name: %s\n    url: %s\n    token_file: %s.token\n    region: eu\n", name, h.srv.URL, name)
	}
	yaml := "listen: " + ctl.Listener.Addr().String() + "\npublic_url: " + ctlURL + "\ncors_origin: http://localhost:5173\n" +
		"admin_token_file: admin.token\npoll_seconds: 0.05\nplayer_hosting: true\n" +
		"oidc:\n  issuer: " + idpURL + "\n  client_id: faf-control\n" + secretLine + "  accept_access_tokens: true\n  required_scope: lobby\n" +
		"roles:\n  admins: [1]\n  organisers: [2]\n" +
		"tournaments:\n  - id: cup\n    name: The Cup\n    organisers: [3]\n    players: [10, 11]\n    observers: [20]\n" +
		"hosts:\n" + hostsYAML.String() + o.extraYAML
	must(os.WriteFile(filepath.Join(dir, "control.yaml"), []byte(yaml), 0o600))
	cfg, err := loadConfig(filepath.Join(dir, "control.yaml"))
	must(err)
	store := o.store
	if store == nil {
		store = newMemStore()
	}
	e.store = store
	ctx, cancel := context.WithCancel(context.Background())
	e.s = newServer(ctx, cfg, filepath.Join(dir, "control.yaml"), store)
	ctl.Config.Handler = e.s
	ctl.Start()
	e.ts = ctl
	t.Cleanup(func() {
		cancel()
		e.s.reg.stop()
		ctl.Close()
	})
	return e
}

// browser is a client with a cookie jar that signs in as uid through the provider.
func (e *env) browser(uid int) *http.Client {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if strings.HasSuffix(req.URL.Path, "/oauth2/auth") {
			q := req.URL.Query()
			q.Set("login_as", strconv.Itoa(uid))
			req.URL.RawQuery = q.Encode()
		}
		return nil
	}}
	resp, err := c.Get(e.ts.URL + "/auth/login?return=/api/v1/me")
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var me struct {
		OK   bool `json:"ok"`
		User struct {
			UID int `json:"uid"`
		} `json:"user"`
	}
	body, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(body, &me) != nil || !me.OK || me.User.UID != uid {
		e.t.Fatalf("sign-in as %d: %d %s", uid, resp.StatusCode, body)
	}
	return c
}

// do sends a request (from the web UI's origin for changes) and decodes the JSON answer.
func (e *env) do(c *http.Client, method, path string, body any, hdr map[string]string) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if method != http.MethodGet {
		req.Header.Set("Origin", "http://localhost:5173")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{"raw": string(b)}
	}
	return resp.StatusCode, out
}

// eventually polls cond for up to 5 s.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (e *env) adminHdr() map[string]string {
	return map[string]string{"Authorization": "Bearer " + e.admin}
}

var _ = url.Values{}
