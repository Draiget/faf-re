package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type api struct {
	token      string
	corsOrigin string
	m          *manager
	maps       func() []Map
	procDir    string
	settings   *settingsSource // plan WP17.20
	hostName   string
	hostLog    *logRing        // the host's own log lines; nil in tests that don't look
	metrics    *metricsHistory // every 2 s, the last hour
	previews   previewCache
	// Plan WPR.16: the RTT echo players probe (public-host:port), "" when off.
	rttEcho string
	echo    *rttEcho
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

// originAllowed says whether a web page at origin may call the API: --cors-origin takes one origin or several,
// comma-separated (e.g. http://localhost:5173,http://127.0.0.1:5173, as browsers may reach a dev server by either).
func (a *api) originAllowed(origin string) bool {
	for _, allowed := range strings.Split(a.corsOrigin, ",") {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	return false
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && a.originAllowed(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p := r.URL.Path
	// Players' requests: no admin token; a request's own key is the credential for following it.
	if rest, ok := strings.CutPrefix(p, "/api/v1/public/"); ok {
		a.public(w, r, rest)
		return
	}
	// A map's preview needs no token either (an <img> can't send one); it is the map file's own picture.
	if rest, ok := strings.CutPrefix(p, "/api/v1/maps/"); ok && strings.HasSuffix(rest, "/preview.png") && r.Method == http.MethodGet {
		a.preview(w, strings.TrimSuffix(rest, "/preview.png"))
		return
	}
	if !a.authorized(r) {
		fail(w, http.StatusUnauthorized, errors.New("missing or wrong admin token"))
		return
	}
	switch {
	case p == "/api/v1/pool" && r.Method == http.MethodGet:
		pool, usage := a.m.poolView()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pool": pool, "usage": usage})
	case p == "/api/v1/pool" && r.Method == http.MethodPut:
		var u PoolUpdate
		dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&u); err != nil {
			fail(w, http.StatusBadRequest, fmt.Errorf("body: %w", err))
			return
		}
		warnings, err := a.m.updatePool(u)
		if err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		pool, usage := a.m.poolView()
		log.Printf("player hosting: %v, pool CPUs %v, up to %d games of %d players, access %s", pool.Enabled, pool.CPUs, pool.MaxGames, pool.MaxPlayers, pool.Access)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pool": pool, "usage": usage, "warnings": warnings})
	case p == "/api/v1/queue" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queue": a.m.listQueue()})
	case strings.HasPrefix(p, "/api/v1/queue/"):
		id, sub, _ := strings.Cut(strings.TrimPrefix(p, "/api/v1/queue/"), "/")
		var err error
		switch {
		case sub == "" && r.Method == http.MethodDelete:
			err = a.m.cancelQueued(id)
		case sub == "up" && r.Method == http.MethodPost:
			err = a.m.moveUp(id)
		default:
			fail(w, http.StatusNotFound, fmt.Errorf("no %s %s", r.Method, p))
			return
		}
		if err != nil {
			fail(w, http.StatusNotFound, err)
			return
		}
		if sub == "" {
			log.Printf("queued %s cancelled by the operator", id)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queue": a.m.listQueue()})
	case p == "/api/v1/metrics" && r.Method == http.MethodGet:
		seconds := 600
		if v := r.URL.Query().Get("seconds"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				fail(w, http.StatusBadRequest, errors.New("seconds is 1..3600"))
				return
			}
			seconds = min(n, 3600)
		}
		if a.metrics == nil {
			writeJSON(w, http.StatusOK, (&metricsHistory{}).window(seconds, time.Now()))
			return
		}
		writeJSON(w, http.StatusOK, a.metrics.window(seconds, time.Now()))
	case p == "/api/v1/logs/host" && r.Method == http.MethodGet:
		lines := []string{}
		if a.hostLog != nil {
			lines = a.hostLog.tail(linesParam(r))
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lines": lines})
	case p == "/api/v1/logs/host/stream" && r.Method == http.MethodGet:
		if a.hostLog == nil {
			fail(w, http.StatusNotFound, errors.New("this host keeps no log"))
			return
		}
		streamRing(w, r, a.hostLog)
	case p == "/api/v1/host" && r.Method == http.MethodGet:
		total, avail := memoryMB(a.procDir)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": map[string]any{
			"name": a.hostName, "cpu_model": cpuModel(a.procDir),
			"memory_mb": map[string]int{"total": total, "available": avail},
			"cpus":      a.m.cpusWithLobbies(), "lobbies": a.liveLobbies(), "ai": aiKeys,
			"nodes": a.m.nodes(), "links": a.m.links(), // plan WP17.16
			"rtt_echo": a.rttEcho, "rtt_echo_counts": a.echoCounts(),
		}})
	case p == "/api/v1/maps" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "maps": a.mapList("/api/v1/maps/")})
	case p == "/api/v1/hint" && r.Method == http.MethodGet:
		players, err1 := strconv.Atoi(r.URL.Query().Get("players"))
		km, err2 := strconv.Atoi(r.URL.Query().Get("km"))
		if err1 != nil || err2 != nil || players < 1 || players > 16 || km < 1 {
			fail(w, http.StatusBadRequest, errors.New("hint takes players=1..16 and km"))
			return
		}
		h := hintFor(players, km)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "players": h.Players, "km": h.KM, "mean_cores": h.MeanCores,
			"worst_cores": h.WorstCores, "suggested_cores": h.SuggestedCores, "basis": h.Basis,
			"min_connection_kbps": h.MinConnectionKBps, "server_upload_kbps": h.ServerUploadKBps, "max_players": h.MaxPlayers,
			"connection_basis": h.ConnectionBasis})
	case p == "/api/v1/plan" && r.Method == http.MethodPost:
		// Plan WP17.17: where a game of this size would go on a side (operator: off the pool while player hosting
		// runs; pool: on its CPUs, its cores per game), and why it may not fit; nothing is started.
		var req struct {
			PlanRequest
			Side string `json:"side"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || req.Players < 1 || req.Players > kMaxPlayers || req.KM < 1 {
			fail(w, http.StatusBadRequest, errors.New("plan takes players 1..16, km, side, and cores or cpus"))
			return
		}
		switch req.Side {
		case "":
			req.Side = "operator"
		case "operator", "pool":
		default:
			fail(w, http.StatusBadRequest, errors.New(`side is "operator" or "pool"`))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "side": req.Side, "plan": a.m.planOn(req.Side, req.PlanRequest)})
	case p == "/api/v1/settings" && r.Method == http.MethodGet:
		a.serveSettings(w, r)
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
		l, queued, code, err := a.m.createOrQueue(req)
		if err != nil {
			log.Printf("lobby not made (%d): %v", code, err)
			fail(w, code, err)
			return
		}
		if queued != nil {
			writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "queued": queued})
			return
		}
		log.Printf("lobby %s (%s): %s on CPUs %v, port %d, pid %d", l.ID, l.Kind, l.Map.Name, l.CPUs, l.Port, l.PID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lobby": l})
	case strings.HasPrefix(p, "/api/v1/lobbies/"):
		rest := strings.TrimPrefix(p, "/api/v1/lobbies/")
		id, sub, _ := strings.Cut(rest, "/")
		switch {
		case sub == "":
			a.lobby(w, r, id)
		case sub == "log" && r.Method == http.MethodGet:
			a.lobbyLog(w, r, id, false)
		case sub == "log/stream" && r.Method == http.MethodGet:
			a.lobbyLog(w, r, id, true)
		default:
			a.proxy(w, r, id, "/"+sub)
		}
	default:
		fail(w, http.StatusNotFound, fmt.Errorf("no %s %s", r.Method, p))
	}
}

// serveSettings answers the lobby options, AIs and, with ?map=<id>, that map's own options, with their defaults (plan
// WP17.20).
func (a *api) serveSettings(w http.ResponseWriter, r *http.Request) {
	var mp *Map
	if id := r.URL.Query().Get("map"); id != "" {
		for _, x := range a.maps() {
			if x.ID == strings.ToLower(id) {
				found := x
				mp = &found
			}
		}
		if mp == nil {
			// 400: the request names a map the host doesn't have (the path itself exists).
			fail(w, http.StatusBadRequest, fmt.Errorf("no map %q", id))
			return
		}
	}
	if a.settings == nil {
		fail(w, http.StatusNotFound, errors.New("this host doesn't describe settings"))
		return
	}
	s, err := a.settings.get(mp)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": s})
}

// mapList is the maps with their preview paths under base.
func (a *api) mapList(base string) []Map {
	maps := a.maps()
	out := make([]Map, len(maps))
	for i, mp := range maps {
		out[i] = mp
		if mp.Preview != "" {
			out[i].Preview = previewPath(base, mp.ID)
		}
	}
	return out
}

// preview answers a map's preview as PNG.
func (a *api) preview(w http.ResponseWriter, id string) {
	var mp *Map
	for _, x := range a.maps() {
		if x.ID == strings.ToLower(id) {
			found := x
			mp = &found
		}
	}
	if mp == nil {
		fail(w, http.StatusNotFound, fmt.Errorf("no map %q", id))
		return
	}
	if mp.Preview == "" {
		fail(w, http.StatusNotFound, fmt.Errorf("map %s has no preview", mp.ID))
		return
	}
	data, err := a.previews.get(mp.scmapFile)
	if err != nil {
		fail(w, http.StatusNotFound, fmt.Errorf("map %s's preview: %v", mp.ID, err))
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// public serves /api/v1/public/... (no admin token): the pool's public face, the maps and settings a player picks
// from, and the requests, each followed with its own key.
func (a *api) public(w http.ResponseWriter, r *http.Request, rest string) {
	pool, usage := a.m.poolView()
	switch {
	case rest == "pool" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": pool.Enabled, "access": pool.Access, "max_players": pool.MaxPlayers,
			"lobby_minutes": pool.LobbyMinutes, "options": pool.Options, "rtt_echo": a.rttEcho,
			"queue": map[string]int{"length": usage.Queued, "games": usage.Games, "max_games": pool.MaxGames}})
	case strings.HasPrefix(rest, "maps/") && strings.HasSuffix(rest, "/preview.png") && r.Method == http.MethodGet:
		a.preview(w, strings.TrimSuffix(strings.TrimPrefix(rest, "maps/"), "/preview.png"))
	case (rest == "maps" || rest == "settings") && r.Method == http.MethodGet:
		if !pool.Enabled {
			fail(w, http.StatusForbidden, errors.New("player hosting is off on this host"))
			return
		}
		if rest == "maps" {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "maps": a.mapList("/api/v1/public/maps/")})
			return
		}
		a.serveSettings(w, r)
	case rest == "requests" && r.Method == http.MethodPost:
		var body RequestBody
		dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			fail(w, http.StatusBadRequest, fmt.Errorf("body: %w", err))
			return
		}
		ip := clientIP(r)
		v, status, err := a.m.submitRequest(body, ip)
		if err != nil {
			log.Printf("request from %s (%s) refused (%d): %v", strings.TrimSpace(body.Player), ip, status, err)
			fail(w, status, err)
			return
		}
		if status != http.StatusOK {
			reason := ""
			if v.Reason != nil {
				reason = *v.Reason
			}
			writeJSON(w, status, map[string]any{"ok": false, "error": reason, "request": v})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request": v})
	case strings.HasPrefix(rest, "requests/") && (r.Method == http.MethodGet || r.Method == http.MethodDelete):
		id := strings.TrimPrefix(rest, "requests/")
		key := r.URL.Query().Get("key")
		if r.Method == http.MethodGet {
			v, err := a.m.getRequest(id, key)
			if err != nil {
				fail(w, http.StatusNotFound, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request": v})
			return
		}
		v, status, err := a.m.cancelRequest(id, key)
		if err != nil {
			if v != nil {
				writeJSON(w, status, map[string]any{"ok": false, "error": err.Error(), "request": v})
				return
			}
			fail(w, status, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request": v})
	default:
		fail(w, http.StatusNotFound, fmt.Errorf("no %s %s", r.Method, r.URL.Path))
	}
}

// lobbyLog answers a lobby's server.log: its last lines, or (stream) its new lines as they come.
func (a *api) lobbyLog(w http.ResponseWriter, r *http.Request, id string, stream bool) {
	l, ok := a.m.get(id)
	if !ok {
		fail(w, http.StatusNotFound, errNoLobby)
		return
	}
	path := filepath.Join(l.Dir, "server.log")
	if stream {
		streamFile(w, r, path, func() bool {
			cur, ok := a.m.get(id)
			return ok && running(cur.State)
		})
		return
	}
	lines, size, err := tailFile(path, linesParam(r))
	if err != nil {
		fail(w, http.StatusNotFound, fmt.Errorf("lobby %s has no log: %v", id, err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lines": lines, "size": size, "state": l.State})
}

// echoCounts is what the RTT echo did since the start: probes answered, packets dropped as malformed, probes over the
// rate limits; nil when it is off.
func (a *api) echoCounts() map[string]int64 {
	if a.echo == nil {
		return nil
	}
	return map[string]int64{"answered": a.echo.answered.Load(), "malformed": a.echo.dropped.Load(), "limited": a.echo.limited.Load()}
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
