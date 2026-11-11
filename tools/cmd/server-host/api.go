package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type api struct {
	token      string
	corsOrigin string
	m          *manager
	maps       func() []Map
	procDir    string
	hostName   string
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]any{"ok": false, "error": err.Error()})
}

func (a *api) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	given, ok := strings.CutPrefix(h, "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(given)), []byte(a.token)) == 1
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.corsOrigin != "" && r.Header.Get("Origin") == a.corsOrigin {
		w.Header().Set("Access-Control-Allow-Origin", a.corsOrigin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !a.authorized(r) {
		fail(w, http.StatusUnauthorized, errors.New("missing or wrong admin token"))
		return
	}
	p := r.URL.Path
	switch {
	case p == "/api/v1/host" && r.Method == http.MethodGet:
		total, avail := memoryMB(a.procDir)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": map[string]any{
			"name": a.hostName, "cpu_model": cpuModel(a.procDir),
			"memory_mb": map[string]int{"total": total, "available": avail},
			"cpus":      a.m.cpusWithLobbies(), "lobbies": a.liveLobbies(), "ai": aiKeys,
		}})
	case p == "/api/v1/maps" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "maps": a.maps()})
	case p == "/api/v1/hint" && r.Method == http.MethodGet:
		players, err1 := strconv.Atoi(r.URL.Query().Get("players"))
		km, err2 := strconv.Atoi(r.URL.Query().Get("km"))
		if err1 != nil || err2 != nil || players < 1 || players > 16 || km < 1 {
			fail(w, http.StatusBadRequest, errors.New("hint takes players=1..16 and km"))
			return
		}
		h := hintFor(players, km)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "players": h.Players, "km": h.KM, "mean_cores": h.MeanCores,
			"worst_cores": h.WorstCores, "suggested_cores": h.SuggestedCores, "basis": h.Basis})
	case p == "/api/v1/lobbies" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lobbies": a.m.list()})
	case p == "/api/v1/lobbies" && r.Method == http.MethodPost:
		var req CreateRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			fail(w, http.StatusBadRequest, fmt.Errorf("body: %w", err))
			return
		}
		l, code, err := a.m.create(req)
		if err != nil {
			fail(w, code, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lobby": l})
	case strings.HasPrefix(p, "/api/v1/lobbies/"):
		rest := strings.TrimPrefix(p, "/api/v1/lobbies/")
		id, sub, _ := strings.Cut(rest, "/")
		if sub == "" {
			a.lobby(w, r, id)
			return
		}
		a.proxy(w, r, id, "/"+sub)
	default:
		fail(w, http.StatusNotFound, fmt.Errorf("no %s %s", r.Method, p))
	}
}

func (a *api) liveLobbies() int {
	n := 0
	for _, l := range a.m.list() {
		if running(l.State) {
			n++
		}
	}
	return n
}

func (a *api) lobby(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		l, ok := a.m.get(id)
		if !ok {
			fail(w, http.StatusNotFound, errNoLobby)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lobby": l})
	case http.MethodDelete:
		if r.URL.Query().Get("forget") == "1" {
			if err := a.m.forget(id); err != nil {
				code := http.StatusConflict
				if errors.Is(err, errNoLobby) {
					code = http.StatusNotFound
				}
				fail(w, code, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			return
		}
		l, err := a.m.stop(id)
		if err != nil {
			fail(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lobby": l})
	default:
		fail(w, http.StatusMethodNotAllowed, errors.New("GET or DELETE"))
	}
}

// proxy hands /api/v1/lobbies/<id>/<sub> to the lobby's own REST API with its token; the events
// stream is passed on as it comes (FlushInterval -1).
func (a *api) proxy(w http.ResponseWriter, r *http.Request, id, sub string) {
	port, token, ok := a.m.childREST(id)
	if !ok {
		fail(w, http.StatusNotFound, fmt.Errorf("lobby %s isn't running", id))
		return
	}
	target := &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(port)}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = sub
			pr.Out.URL.RawPath = ""
			pr.Out.Host = target.Host
			pr.Out.Header.Set("Authorization", "Bearer "+token)
			pr.Out.Header.Del("Origin")
		},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Max-Age", "Vary"} {
				resp.Header.Del(h) // the host's own CORS headers stand
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			fail(w, http.StatusBadGateway, fmt.Errorf("lobby %s's server didn't answer: %v", id, err))
		},
	}
	rp.ServeHTTP(w, r)
}

func hostName() string {
	if b, err := os.ReadFile("/etc/hostname"); err == nil && strings.TrimSpace(string(b)) != "" {
		return strings.TrimSpace(string(b))
	}
	n, _ := os.Hostname()
	return n
}
