package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// server is the control service's HTTP side.
type server struct {
	cfgPath string
	cfg     atomic.Pointer[Config]
	oidc    atomic.Pointer[oidcClient]
	store   Store
	reg     *registry
	hub     *hub
	ctx     context.Context // the service's lifetime
	// httpClient is used for the OpenID provider (tests swap it).
	httpClient *http.Client
}

func newServer(ctx context.Context, cfg *Config, cfgPath string, store Store) *server {
	s := &server{cfgPath: cfgPath, store: store, reg: newRegistry(store), ctx: ctx,
		httpClient: &http.Client{Timeout: 15 * time.Second}}
	s.hub = newHub(s)
	s.hub.start() // subscribed before the pollers publish anything
	s.apply(cfg)
	return s
}

// apply makes cfg the configuration in force: roles and tournaments at once, the OpenID client when its settings
// changed, the hosts' pollers.
func (s *server) apply(cfg *Config) {
	old := s.cfg.Swap(cfg)
	if old == nil || old.OIDC.Issuer != cfg.OIDC.Issuer || old.OIDC.ClientID != cfg.OIDC.ClientID ||
		old.clientSecret != cfg.clientSecret || old.OIDC.RedirectURL != cfg.OIDC.RedirectURL ||
		!slices.Equal(old.OIDC.Scopes, cfg.OIDC.Scopes) {
		s.oidc.Store(&oidcClient{issuer: strings.TrimRight(cfg.OIDC.Issuer, "/"), clientID: cfg.OIDC.ClientID,
			secret: cfg.clientSecret, redirect: cfg.OIDC.RedirectURL, scopes: cfg.OIDC.Scopes, http: s.httpClient})
	}
	s.reg.apply(s.ctx, cfg.Hosts, cfg.pollInterval())
}

// reload reads the configuration file again.
func (s *server) reload() error {
	cfg, err := loadConfig(s.cfgPath)
	if err != nil {
		return err
	}
	s.apply(cfg)
	log.Printf("configuration reloaded: %d hosts, %d tournaments, %d admins, %d organisers", len(cfg.Hosts),
		len(cfg.Tournaments), len(cfg.Roles.Admins), len(cfg.Roles.Organisers))
	return nil
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

var (
	errSignIn    = errors.New("sign in first (missing, expired or wrong credentials)")
	errForbidden = errors.New("your roles don't allow this")
)

// allowedOrigin: the service's own origin and the configured web UI's.
func (cfg *Config) allowedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	pu, _ := url.Parse(cfg.PublicURL)
	return origin == pu.Scheme+"://"+pu.Host || (cfg.CORSOrigin != "" && origin == cfg.CORSOrigin)
}

// authenticate finds who sent the request: the admin token, a FAF access token (when accepted) or a session cookie.
// Cookie-authenticated requests that change something must come from an allowed origin (the cookie is SameSite=Lax
// as well).
func (s *server) authenticate(r *http.Request) (Principal, error) {
	cfg := s.cfg.Load()
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		bearer = strings.TrimSpace(bearer)
		if cfg.adminToken != "" && subtle.ConstantTimeCompare([]byte(bearer), []byte(cfg.adminToken)) == 1 {
			return Principal{Name: "admin token", Admin: true, Via: "admin_token"}, nil
		}
		if !cfg.OIDC.AcceptAccessTokens {
			return Principal{}, errSignIn
		}
		uid, err := s.oidc.Load().verifyAccessToken(r.Context(), bearer, cfg.OIDC.RequiredScope)
		if err != nil {
			return Principal{}, fmt.Errorf("%w: %v", errSignIn, err)
		}
		return cfg.principal(uid, fmt.Sprintf("FAF user %d", uid), "access_token"), nil
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return Principal{}, errSignIn
	}
	v, ok, err := s.store.Get(r.Context(), sessionKey(c.Value))
	if err != nil {
		return Principal{}, fmt.Errorf("session store: %w", err)
	}
	if !ok {
		return Principal{}, errSignIn
	}
	var ss session
	if json.Unmarshal([]byte(v), &ss) != nil {
		return Principal{}, errSignIn
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !cfg.allowedOrigin(r.Header.Get("Origin")) {
		return Principal{}, errors.New("a signed-in browser's change must come from the service's or the web UI's origin")
	}
	return cfg.principal(ss.UID, ss.Name, "session"), nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Load()
	if origin := r.Header.Get("Origin"); cfg.CORSOrigin != "" && origin == cfg.CORSOrigin {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
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
	switch {
	case p == "/api/v1/health" && r.Method == http.MethodGet:
		up := 0
		for _, pl := range s.reg.all() {
			if h, _ := pl.state(); h.Reachable {
				up++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "store": s.store.Kind(), "hosts": len(cfg.Hosts), "hosts_reachable": up})
		return
	case p == "/auth/login" && r.Method == http.MethodGet:
		s.login(w, r)
		return
	case p == "/auth/callback" && r.Method == http.MethodGet:
		s.callback(w, r)
		return
	case p == "/auth/logout" && r.Method == http.MethodPost:
		s.logout(w, r)
		return
	}
	if !strings.HasPrefix(p, "/api/v1/") {
		fail(w, http.StatusNotFound, fmt.Errorf("no %s %s", r.Method, p))
		return
	}
	who, err := s.authenticate(r)
	if err != nil {
		code := http.StatusUnauthorized
		if strings.Contains(err.Error(), "origin") {
			code = http.StatusForbidden
		} else if strings.HasPrefix(err.Error(), "session store") {
			code = http.StatusServiceUnavailable
		}
		fail(w, code, err)
		return
	}
	rest := strings.TrimPrefix(p, "/api/v1/")
	switch {
	case rest == "me" && r.Method == http.MethodGet:
		s.me(w, cfg, who)
	case rest == "events" && r.Method == http.MethodGet:
		s.hub.serve(w, r, who)
	case rest == "hosts" && r.Method == http.MethodGet:
		out := []any{}
		for _, pl := range s.reg.all() {
			h, _ := pl.state()
			out = append(out, hostView(cfg, who, h))
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hosts": out})
	case strings.HasPrefix(rest, "hosts/"):
		s.hostRead(w, r, cfg, who, strings.TrimPrefix(rest, "hosts/"))
	case rest == "tournaments" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tournaments": tournamentsFor(cfg, who)})
	case rest == "lobbies" && r.Method == http.MethodGet:
		s.listLobbies(w, r, cfg, who)
	case rest == "lobbies" && r.Method == http.MethodPost:
		s.createLobby(w, r, cfg, who)
	case strings.HasPrefix(rest, "lobbies/"):
		s.lobbyRoute(w, r, cfg, who, strings.TrimPrefix(rest, "lobbies/"))
	case rest == "requests" && (r.Method == http.MethodGet || r.Method == http.MethodPost):
		if r.Method == http.MethodGet {
			s.listRequests(w, r, who)
		} else {
			s.submitRequest(w, r, cfg, who)
		}
	case strings.HasPrefix(rest, "requests/"):
		s.requestRoute(w, r, who, strings.TrimPrefix(rest, "requests/"))
	case rest == "admin/reload" && r.Method == http.MethodPost:
		if !who.Admin {
			fail(w, http.StatusForbidden, errForbidden)
			return
		}
		if err := s.reload(); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		fail(w, http.StatusNotFound, fmt.Errorf("no %s %s", r.Method, p))
	}
}

func (s *server) me(w http.ResponseWriter, cfg *Config, who Principal) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": who, "roles": cfg.roles(who),
		"tournaments": tournamentsFor(cfg, who), "player_hosting": cfg.PlayerHosting})
}

// tournamentsFor: admins and global organisers see every tournament with its lists; others the ones they are in,
// with their part in each (organiser, player, observer), and the lists only where they organise.
func tournamentsFor(cfg *Config, who Principal) []map[string]any {
	out := []map[string]any{}
	for _, t := range cfg.Tournaments {
		parts := []string{}
		if slices.Contains(t.Organisers, who.UID) && who.UID != 0 {
			parts = append(parts, "organiser")
		}
		if slices.Contains(t.Players, who.UID) && who.UID != 0 {
			parts = append(parts, "player")
		}
		if slices.Contains(t.Observers, who.UID) && who.UID != 0 {
			parts = append(parts, "observer")
		}
		all := who.Admin || who.Organiser
		if !all && len(parts) == 0 {
			continue
		}
		m := map[string]any{"id": t.ID, "name": t.Name, "you": parts}
		if all || slices.Contains(parts, "organiser") {
			m["organisers"], m["players"], m["observers"] = nonNil(t.Organisers), nonNil(t.Players), nonNil(t.Observers)
		}
		out = append(out, m)
	}
	return out
}

func nonNil(v []int) []int {
	if v == nil {
		return []int{}
	}
	return v
}

// login starts a sign-in: GET /auth/login?return=<where to go afterwards>.
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Load()
	ret := r.URL.Query().Get("return")
	if !safeReturn(cfg, ret) {
		ret = "/"
	}
	target, state, ls, err := s.oidc.Load().authURL(r.Context())
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	ls.Return = ret
	b, _ := json.Marshal(ls)
	if err := s.store.Set(r.Context(), "login:"+state, string(b), 10*time.Minute); err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("session store: %w", err))
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// safeReturn: a path on this service, or a URL on the web UI's origin; nothing else (no open redirect).
func safeReturn(cfg *Config, ret string) bool {
	if ret == "" {
		return false
	}
	if strings.HasPrefix(ret, "/") && !strings.HasPrefix(ret, "//") && !strings.Contains(ret, `\`) {
		return true
	}
	u, err := url.Parse(ret)
	return err == nil && u.User == nil && cfg.allowedOrigin(u.Scheme+"://"+u.Host)
}

// callback finishes a sign-in: the provider sends the browser back with ?code and ?state.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Load()
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail(w, http.StatusUnauthorized, fmt.Errorf("sign-in refused by the provider: %s %s", e, q.Get("error_description")))
		return
	}
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		fail(w, http.StatusBadRequest, errors.New("the callback needs code and state"))
		return
	}
	v, ok, err := s.store.Take(r.Context(), "login:"+state)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("session store: %w", err))
		return
	}
	var ls loginState
	if !ok || json.Unmarshal([]byte(v), &ls) != nil {
		fail(w, http.StatusBadRequest, errors.New("unknown or used sign-in state: start again"))
		return
	}
	uid, name, err := s.oidc.Load().exchange(r.Context(), code, ls)
	if err != nil {
		log.Printf("sign-in failed: %v", err)
		fail(w, http.StatusUnauthorized, fmt.Errorf("sign-in failed: %v", err))
		return
	}
	id := randomToken(32)
	b, _ := json.Marshal(session{UID: uid, Name: name, Created: time.Now().UTC().Format(time.RFC3339)})
	if err := s.store.Set(r.Context(), sessionKey(id), string(b), cfg.sessionTTL()); err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("session store: %w", err))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: strings.HasPrefix(cfg.PublicURL, "https://"), SameSite: http.SameSiteLaxMode,
		MaxAge: int(cfg.sessionTTL().Seconds())})
	log.Printf("signed in: %s (FAF %d), roles %v", name, uid, cfg.roles(cfg.principal(uid, name, "session")))
	http.Redirect(w, r, ls.Return, http.StatusFound)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Load()
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if !cfg.allowedOrigin(r.Header.Get("Origin")) {
			fail(w, http.StatusForbidden, errors.New("sign out from the service's or the web UI's origin"))
			return
		}
		_ = s.store.Del(r.Context(), sessionKey(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
		Secure: strings.HasPrefix(cfg.PublicURL, "https://"), SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
