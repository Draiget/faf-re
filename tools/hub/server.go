package hub

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"faf-main/tools/bus"
	"faf-main/tools/journal"
	"faf-main/tools/relay"
)

// Options configure the hub's control and relay services.
type Options struct {
	// Secret authenticates every /hub request (Authorization: Bearer).
	// Empty is only acceptable on a loopback-only hub.
	Secret string
	// PublicHost is the name (or address) machines use to reach this hub; it
	// is handed to directors for relay addresses. Keep it a DNS name.
	PublicHost string
	// RelayListenIP binds relay sockets (nil: every interface).
	RelayListenIP net.IP
	// RelayMinPort..RelayMaxPort is the relay's port pool (0: any port).
	RelayMinPort, RelayMaxPort int
}

// AgentInfo is what the hub knows about one agent.
type AgentInfo struct {
	Name      string    `json:"name"`
	Listening bool      `json:"listening"`
	Since     time.Time `json:"since"`
	Remote    string    `json:"remote"`
}

type runRelay struct {
	relay *relay.Relay
	box   string
}

// Server is the hub's HTTP side; mount it with Routes.
type Server struct {
	opts Options
	j    *journal.Journal
	bus  *bus.Bus

	mu      sync.Mutex
	agents  map[string]*AgentInfo
	relays  map[string]*runRelay
	watches map[uint64]string // game id -> director mailbox for its ICE/TURN records
}

// New creates a hub server on a shared queue.
func New(opts Options, j *journal.Journal, b *bus.Bus) *Server {
	return &Server{opts: opts, j: j, bus: b, agents: map[string]*AgentInfo{},
		relays: map[string]*runRelay{}, watches: map[uint64]string{}}
}

// Routes registers the hub API on mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /hub/info", s.auth(s.handleInfo))
	mux.HandleFunc("GET /hub/agents", s.auth(s.handleAgents))
	mux.HandleFunc("POST /hub/send/{box...}", s.auth(s.handleSend))
	mux.HandleFunc("GET /hub/listen/{box...}", s.auth(s.handleListen))
	mux.HandleFunc("POST /hub/watch", s.auth(s.handleWatch))
	mux.HandleFunc("POST /hub/relay/{run}/links", s.auth(s.handleRelayLink))
	mux.HandleFunc("POST /hub/relay/{run}/impair", s.auth(s.handleRelayImpair))
	mux.HandleFunc("POST /hub/relay/{run}/isolate", s.auth(s.handleRelayIsolate))
	mux.HandleFunc("GET /hub/relay/{run}/stats", s.auth(s.handleRelayStats))
	mux.HandleFunc("DELETE /hub/relay/{run}", s.auth(s.handleRelayClose))
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.opts.Secret)) != 1 {
			http.Error(w, "hub: bad or missing secret", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Forward is the hub journal's echo hook: ICE and TURN records of a watched
// game are copied to the director running it, so its assertions (relay
// candidates, TURN allocations) work when those services are remote.
func (s *Server) Forward(r journal.Record) {
	if r.Game == 0 || !(strings.HasPrefix(r.Kind, "ice.") || strings.HasPrefix(r.Kind, "turn.")) {
		return
	}
	s.mu.Lock()
	box := s.watches[r.Game]
	s.mu.Unlock()
	if box != "" {
		s.publish(box, Envelope{Type: TypeRecord, Record: ToWire(r)})
	}
}

func (s *Server) publish(box string, env Envelope) {
	raw, _ := json.Marshal(env)
	s.bus.Publish("hub/"+box, raw)
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"publicHost": s.opts.PublicHost,
		"relayPorts": []int{s.opts.RelayMinPort, s.opts.RelayMaxPort}})
}

func (s *Server) handleAgents(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make([]AgentInfo, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, *a)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, k int) bool { return out[i].Name < out[k].Name })
	writeJSON(w, out)
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	box := r.PathValue("box")
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil || !json.Valid(raw) {
		http.Error(w, "hub: body must be one JSON envelope", http.StatusBadRequest)
		return
	}
	s.bus.Publish("hub/"+box, raw)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListen(w http.ResponseWriter, r *http.Request) {
	box := r.PathValue("box")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // behind nginx: do not buffer the stream
	w.WriteHeader(http.StatusOK)

	var mu sync.Mutex
	write := func(chunk string) error {
		mu.Lock()
		defer mu.Unlock()
		if _, err := io.WriteString(w, chunk); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
	if write(": hub stream\n\n") != nil {
		return
	}

	agent, isAgent := strings.CutPrefix(box, "agent/")
	if isAgent {
		s.mu.Lock()
		s.agents[agent] = &AgentInfo{Name: agent, Listening: true, Since: time.Now(), Remote: r.RemoteAddr}
		s.mu.Unlock()
		s.j.Add(journal.Record{Kind: journal.Note, Text: "agent connected: " + agent})
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
	s.bus.Subscribe(ctx, "hub/"+box, func(p []byte) error { return write("data: " + string(p) + "\n\n") })

	if isAgent {
		s.mu.Lock()
		if a := s.agents[agent]; a != nil && a.Remote == r.RemoteAddr {
			a.Listening = false
		}
		s.mu.Unlock()
		s.j.Add(journal.Record{Kind: journal.Note, Text: "agent disconnected: " + agent})
	}
}

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Game uint64 `json:"game"`
		Box  string `json:"box"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Game == 0 || req.Box == "" {
		http.Error(w, "hub: body must be {\"game\":<id>,\"box\":\"run/...\"}", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.watches[req.Game] = req.Box
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// runRelayFor returns (creating on demand) the latching relay of one run. Its
// records are forwarded to the run's director.
func (s *Server) runRelayFor(run, box string) (*relay.Relay, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rr := s.relays[run]; rr != nil {
		return rr.relay, nil
	}
	if box == "" {
		return nil, fmt.Errorf("hub: no relay for run %q", run)
	}
	rj, err := journal.New("", func(r journal.Record) {
		s.publish(box, Envelope{Type: TypeRecord, Run: run, Record: ToWire(r)})
	})
	if err != nil {
		return nil, err
	}
	listen := s.opts.RelayListenIP
	if listen == nil {
		listen = net.IPv4zero
	}
	rl := relay.New(rj, relay.Options{Latch: true, ListenIP: listen,
		MinPort: s.opts.RelayMinPort, MaxPort: s.opts.RelayMaxPort})
	s.relays[run] = &runRelay{relay: rl, box: box}
	s.j.Add(journal.Record{Kind: journal.Note, Text: "relay opened for run " + run})
	return rl, nil
}

func (s *Server) handleRelayLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Box  string `json:"box"`
		A, B int
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "hub: bad link request", http.StatusBadRequest)
		return
	}
	rl, err := s.runRelayFor(r.PathValue("run"), req.Box)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	link, err := rl.Ensure(req.A, req.B, nil, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	portA, portB := link.PortForA(), link.PortForB()
	if link.A != req.A { // the relay orders pairs; answer in the caller's order
		portA, portB = portB, portA
	}
	writeJSON(w, map[string]any{"host": s.opts.PublicHost, "portForA": portA, "portForB": portB})
}

func (s *Server) handleRelayImpair(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From, To   int
		Both       bool
		Impairment relay.Impairment
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "hub: bad impairment request", http.StatusBadRequest)
		return
	}
	rl, err := s.runRelayFor(r.PathValue("run"), "")
	if err == nil {
		err = rl.Set(req.From, req.To, req.Impairment, req.Both)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRelayIsolate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UID     int
		Blocked bool
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "hub: bad isolate request", http.StatusBadRequest)
		return
	}
	rl, err := s.runRelayFor(r.PathValue("run"), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rl.Isolate(req.UID, req.Blocked)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRelayStats(w http.ResponseWriter, r *http.Request) {
	rl, err := s.runRelayFor(r.PathValue("run"), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, rl.Stats())
}

func (s *Server) handleRelayClose(w http.ResponseWriter, r *http.Request) {
	run := r.PathValue("run")
	s.mu.Lock()
	rr := s.relays[run]
	delete(s.relays, run)
	for game, box := range s.watches {
		if box == RunBox(run) {
			delete(s.watches, game)
		}
	}
	s.mu.Unlock()
	if rr != nil {
		rr.relay.Close()
		s.j.Add(journal.Record{Kind: journal.Note, Text: "relay closed for run " + run})
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
