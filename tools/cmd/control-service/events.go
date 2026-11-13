package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// hub fans the store's event channel out to the web clients' SSE streams, each seeing what its viewer may see.
type hub struct {
	s       *server
	mu      sync.Mutex
	clients map[chan event]bool
	once    sync.Once
}

func newHub(s *server) *hub { return &hub{s: s, clients: map[chan event]bool{}} }

// start subscribes to the store's channel (once) and hands every event to every client; a client whose buffer is
// full loses it (its next state event carries the whole lobby again).
func (h *hub) start() {
	h.once.Do(func() {
		ch, err := h.s.store.Subscribe(h.s.ctx, eventsChannel)
		if err != nil {
			log.Printf("events: subscribe: %v", err)
			return
		}
		go func() {
			for msg := range ch {
				var e event
				if json.Unmarshal([]byte(msg), &e) != nil {
					continue
				}
				h.mu.Lock()
				for c := range h.clients {
					select {
					case c <- e:
					default:
					}
				}
				h.mu.Unlock()
			}
		}()
	})
}

func (h *hub) add() chan event {
	c := make(chan event, 256)
	h.mu.Lock()
	h.clients[c] = true
	h.mu.Unlock()
	return c
}

func (h *hub) remove(c chan event) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

func (h *hub) clientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// serve is GET /api/v1/events[?lobby=<host>/<id>]: Server-Sent Events. First `snapshot` (the hosts and lobbies now),
// then `host`, `host_removed`, `lobby`, `lobby_removed` and, for those who run a lobby, `lobby_event` (the lobby
// server's own events, relayed). A comment line every 15 s keeps proxies from closing the stream.
func (h *hub) serve(w http.ResponseWriter, r *http.Request, who Principal) {
	fl, ok := w.(http.Flusher)
	if !ok {
		fail(w, http.StatusInternalServerError, fmt.Errorf("streaming unsupported"))
		return
	}
	only := r.URL.Query().Get("lobby")
	c := h.add() // before the snapshot, so nothing between the two is lost
	defer h.remove(c)
	cfg := h.s.cfg.Load()
	lobbies, err := h.s.cachedLobbies(r.Context())
	if err != nil {
		fail(w, http.StatusServiceUnavailable, fmt.Errorf("store: %w", err))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	hosts := []any{}
	for _, p := range h.s.reg.all() {
		hs, _ := p.state()
		hosts = append(hosts, hostView(cfg, who, hs))
	}
	views := []lobbyView{}
	for _, st := range lobbies {
		if only == "" || st.Key == only {
			views = append(views, viewLobby(cfg, who, st))
		}
	}
	send := func(name string, v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, strings.ReplaceAll(string(b), "\n", ""))
		fl.Flush()
	}
	send("snapshot", map[string]any{"hosts": hosts, "lobbies": views})
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-h.s.ctx.Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case e := <-c:
			cfg := h.s.cfg.Load()
			switch e.Type {
			case "host":
				if only == "" && e.Host != nil {
					send("host", hostView(cfg, who, *e.Host))
				}
			case "host_removed":
				if only == "" {
					send("host_removed", map[string]string{"name": e.Key})
				}
			case "lobby":
				if e.Lobby != nil && (only == "" || only == e.Key) {
					send("lobby", viewLobby(cfg, who, e.Lobby))
				}
			case "lobby_removed":
				if only == "" || only == e.Key {
					send("lobby_removed", map[string]string{"key": e.Key})
				}
			case "lobby_event":
				if (only == "" || only == e.Key) && canSeeAll(cfg, who, e.Meta) {
					send("lobby_event", map[string]any{"key": e.Key, "event": e.Event, "data": e.Data})
				}
			}
		}
	}
}
