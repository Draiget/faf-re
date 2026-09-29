// Package icebreaker is a local stand-in for faf-icebreaker, the signalling
// service faf-pioneer (the WebRTC ICE adapter) talks to. It serves the same
// REST + server-sent-events API the adapter's client uses
// (faf-pioneer/icebreaker/icebreaker.go):
//
//	POST /session/token                  access token -> session token
//	GET  /session/game/{id}              ICE servers (the embedded TURN)
//	POST /session/game/{id}/events       candidates / peerClosing from a peer
//	GET  /session/game/{id}/events       SSE stream of events for this peer
//	POST /session/game/{id}/logs         adapter log upload
//
// State lives in memory (the "DB"), routing goes through package bus (the
// "queue"), and TURN is package turnsrv (the "eturnal"). Nothing needs Docker.
package icebreaker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"faf-main/tools/bus"
	"faf-main/tools/journal"
	"faf-main/tools/turnsrv"
)

// Options configure the server.
type Options struct {
	// ForceRelay is returned as the session's forceRelay flag, which makes the
	// adapter use TURN relay candidates only.
	ForceRelay bool
	// Turn supplies ICE servers; nil hands out none (host candidates only).
	Turn *turnsrv.Server
	// LogDir receives uploaded adapter logs, one JSONL file per user.
	LogDir string
	// State, when set, adds caller state to GET /debug/state.
	State func() any
	// Secret, when set, requires access tokens signed with it (HS256, see
	// MintAccessToken). Leave empty only on a loopback-only server.
	Secret string
	// Bus lets the icebreaker share a queue with other services on the same
	// server; nil creates a private one.
	Bus *bus.Bus
}

// iceKey is a peer's mailbox on the bus.
func iceKey(gameID uint64, uid uint) string { return fmt.Sprintf("ice/%d/%d", gameID, uid) }

type member struct {
	UID        uint      `json:"uid"`
	FirstSeen  time.Time `json:"firstSeen"`
	Streams    int       `json:"streams"`
	Listening  int       `json:"listening"`
	EventsSent int       `json:"eventsSent"`
}

type game struct {
	ID      uint64
	Members map[uint]*member
}

type session struct {
	UID    uint
	GameID uint64
}

// Server is the HTTP service.
type Server struct {
	opts Options
	j    *journal.Journal
	bus  *bus.Bus

	mu       sync.Mutex
	games    map[uint64]*game
	sessions map[string]session
	logMu    sync.Mutex

	http *http.Server
	ln   net.Listener
}

// New creates a server; call Start to serve.
func New(opts Options, j *journal.Journal) *Server {
	b := opts.Bus
	if b == nil {
		b = bus.New()
	}
	return &Server{
		opts:     opts,
		j:        j,
		bus:      b,
		games:    make(map[uint64]*game),
		sessions: make(map[string]session),
	}
}

// Start listens on addr ("127.0.0.1:0" picks a port) and serves in the background.
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("icebreaker listen %s: %w", addr, err)
	}
	s.ln = ln
	s.http = &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = s.http.Serve(ln) }()
	return nil
}

// URL is the API root to pass as faf-pioneer's --api-root.
func (s *Server) URL() string { return "http://" + s.ln.Addr().String() }

// Close stops serving and ends every event stream.
func (s *Server) Close() {
	if s.http != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.http.Shutdown(ctx)
		_ = s.http.Close()
	}
}

// Handler exposes the routes on their own mux (also used directly by tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.Routes(mux)
	return mux
}

// Routes registers the icebreaker API on mux, so one HTTP server can host it
// next to other services.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /session/token", s.handleToken)
	mux.HandleFunc("GET /session/game/{game}", s.handleSession)
	mux.HandleFunc("POST /session/game/{game}/events", s.handlePostEvent)
	mux.HandleFunc("GET /session/game/{game}/events", s.handleEventStream)
	mux.HandleFunc("POST /session/game/{game}/logs", s.handleLogs)
	mux.HandleFunc("GET /debug/state", s.handleState)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) memberLocked(gameID uint64, uid uint) *member {
	g := s.games[gameID]
	if g == nil {
		g = &game{ID: gameID, Members: make(map[uint]*member)}
		s.games[gameID] = g
	}
	m := g.Members[uid]
	if m == nil {
		m = &member{UID: uid, FirstSeen: time.Now()}
		g.Members[uid] = m
	}
	return m
}

// authorize resolves the session token of a request against the path's game.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) (session, bool) {
	gameID, err := strconv.ParseUint(r.PathValue("game"), 10, 64)
	if err != nil {
		http.Error(w, "bad game id", http.StatusBadRequest)
		return session{}, false
	}
	s.mu.Lock()
	sess, ok := s.sessions[bearer(r)]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unknown session token", http.StatusUnauthorized)
		return session{}, false
	}
	if sess.GameID != gameID {
		http.Error(w, "session token is for another game", http.StatusForbidden)
		return session{}, false
	}
	return sess, true
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	uid, claims, err := VerifyAccessToken(bearer(r), s.opts.Secret)
	if err != nil {
		http.Error(w, "invalid access token: "+err.Error(), http.StatusUnauthorized)
		return
	}
	var req struct {
		GameID uint64 `json:"gameId"`
	}
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil || req.GameID == 0 {
		http.Error(w, "body must be {\"gameId\": <id>}", http.StatusBadRequest)
		return
	}
	if claims.Ext.GameID != 0 && claims.Ext.GameID != req.GameID {
		s.j.Note(journal.Warn, int(uid), fmt.Sprintf("access token is for game %d, session asked for %d",
			claims.Ext.GameID, req.GameID), nil)
	}

	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	token := fmt.Sprintf("mpemu.%d.%d.%s", req.GameID, uid, hex.EncodeToString(buf))

	s.mu.Lock()
	s.sessions[token] = session{UID: uid, GameID: req.GameID}
	s.memberLocked(req.GameID, uid)
	s.mu.Unlock()

	s.j.Add(journal.Record{Kind: journal.IceSession, Game: req.GameID, UID: int(uid), Text: "token",
		Data: map[string]any{"game": req.GameID}})
	writeJSON(w, http.StatusOK, map[string]string{"jwt": token})
}

type iceServer struct {
	ID         string   `json:"id"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
	URLs       []string `json:"urls"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.authorize(w, r)
	if !ok {
		return
	}
	servers := []iceServer{}
	if s.opts.Turn != nil {
		user, pass := s.opts.Turn.Credentials(sess.GameID, sess.UID, 24*time.Hour)
		servers = append(servers, iceServer{ID: "mpemu-turn", Username: user, Credential: pass,
			URLs: s.opts.Turn.URLs()})
	}
	s.j.Add(journal.Record{Kind: journal.IceSession, Game: sess.GameID, UID: int(sess.UID), Text: "session",
		Data: map[string]any{"forceRelay": s.opts.ForceRelay, "servers": len(servers)}})
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         strconv.FormatUint(sess.GameID, 10),
		"forceRelay": s.opts.ForceRelay,
		"servers":    servers,
	})
}

// others lists the game's members except uid, in a stable order.
func (s *Server) othersLocked(gameID uint64, uid uint) []uint {
	var out []uint
	if g := s.games[gameID]; g != nil {
		for id := range g.Members {
			if id != uid {
				out = append(out, id)
			}
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

func (s *Server) handlePostEvent(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.authorize(w, r)
	if !ok {
		return
	}
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	var ev map[string]any
	if err := dec.Decode(&ev); err != nil {
		http.Error(w, "invalid event json", http.StatusBadRequest)
		return
	}
	eventType, _ := ev["eventType"].(string)
	if claimed, ok := ev["senderId"].(json.Number); ok && claimed.String() != strconv.Itoa(int(sess.UID)) {
		s.j.Note(journal.Warn, int(sess.UID), "event senderId "+claimed.String()+" rewritten to the session user", nil)
	}
	ev["senderId"] = sess.UID
	ev["gameId"] = sess.GameID

	var recipients []uint
	targeted := false
	if rv, ok := ev["recipientId"].(json.Number); ok {
		if id, err := strconv.ParseUint(rv.String(), 10, 32); err == nil {
			recipients = []uint{uint(id)}
			targeted = true
		}
	}

	s.mu.Lock()
	if !targeted {
		recipients = s.othersLocked(sess.GameID, sess.UID)
	}
	s.memberLocked(sess.GameID, sess.UID).EventsSent++
	s.mu.Unlock()

	payload, _ := json.Marshal(ev)
	for _, to := range recipients {
		s.bus.Publish(iceKey(sess.GameID, to), payload)
	}

	data := map[string]any{"bytes": len(payload), "to": recipients}
	if cands, ok := ev["candidates"].([]any); ok {
		data["candidates"] = len(cands)
		data["types"] = candidateTypes(cands)
	}
	peer := 0
	if targeted {
		peer = int(recipients[0])
	}
	s.j.Add(journal.Record{Kind: journal.IceEvent, Game: sess.GameID, UID: int(sess.UID), Peer: peer, Text: eventType, Data: data})
	w.WriteHeader(http.StatusNoContent)
}

// candidateTypes summarises ICE candidate types (host/srflx/relay) for the journal.
func candidateTypes(cands []any) map[string]int {
	out := map[string]int{}
	for _, c := range cands {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		t, _ := m["typ"].(string)
		if t == "" {
			t, _ = m["type"].(string)
		}
		out[t]++
	}
	return out
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.authorize(w, r)
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	var writeMu sync.Mutex
	write := func(chunk string) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if _, err := io.WriteString(w, chunk); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
	if write(": mpemu event stream\n\n") != nil {
		return
	}

	s.mu.Lock()
	m := s.memberLocked(sess.GameID, sess.UID)
	m.Streams++
	m.Listening++
	others := s.othersLocked(sess.GameID, sess.UID)
	s.mu.Unlock()
	s.j.Add(journal.Record{Kind: journal.IceSub, Game: sess.GameID, UID: int(sess.UID)})

	// Tell everyone else this peer is reachable now, as faf-icebreaker does.
	connected, _ := json.Marshal(map[string]any{"eventType": "connected", "gameId": sess.GameID, "senderId": sess.UID})
	for _, to := range others {
		s.bus.Publish(iceKey(sess.GameID, to), connected)
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if write(": keepalive\n\n") != nil {
					cancel()
					return
				}
			}
		}
	}()

	s.bus.Subscribe(ctx, iceKey(sess.GameID, sess.UID), func(p []byte) error {
		return write("data: " + string(p) + "\n\n")
	})

	s.mu.Lock()
	m.Listening--
	s.mu.Unlock()
	s.j.Add(journal.Record{Kind: journal.IceUnsub, Game: sess.GameID, UID: int(sess.UID)})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.authorize(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	var entries []json.RawMessage
	_ = json.Unmarshal(body, &entries)
	if s.opts.LogDir != "" && len(entries) > 0 {
		s.logMu.Lock()
		path := filepath.Join(s.opts.LogDir, fmt.Sprintf("adapter-remote-log-%d.jsonl", sess.UID))
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			var b bytes.Buffer
			for _, e := range entries {
				b.Write(e)
				b.WriteByte('\n')
			}
			_, _ = f.Write(b.Bytes())
			_ = f.Close()
		}
		s.logMu.Unlock()
	}
	s.j.Add(journal.Record{Kind: journal.IceLogs, Game: sess.GameID, UID: int(sess.UID), Data: map[string]any{"entries": len(entries)}})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	type memberState struct {
		member
		Pending int `json:"pending"`
		Dropped int `json:"dropped"`
	}
	s.mu.Lock()
	games := map[string][]memberState{}
	for id, g := range s.games {
		var ms []memberState
		for _, m := range g.Members {
			ms = append(ms, memberState{member: *m})
		}
		sort.Slice(ms, func(a, b int) bool { return ms[a].UID < ms[b].UID })
		games[strconv.FormatUint(id, 10)] = ms
	}
	sessions := len(s.sessions)
	s.mu.Unlock()
	for id, ms := range games {
		gid, _ := strconv.ParseUint(id, 10, 64)
		for i := range ms {
			ms[i].Pending, ms[i].Dropped = s.bus.Pending(iceKey(gid, ms[i].UID))
		}
	}

	out := map[string]any{"games": games, "sessions": sessions, "forceRelay": s.opts.ForceRelay}
	if s.opts.Turn != nil {
		out["turn"] = map[string]any{"addr": s.opts.Turn.Addr(), "allocations": s.opts.Turn.Allocations()}
	}
	if s.opts.State != nil {
		out["run"] = s.opts.State()
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
