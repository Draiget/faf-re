package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type sseEvent struct {
	name string
	data map[string]any
}

// openStream opens /api/v1/events for a client and delivers its events.
func openStream(t *testing.T, e *env, c *http.Client, query string) <-chan sseEvent {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, e.ts.URL+"/api/v1/events"+query, nil)
	sc := *c
	sc.Timeout = 0
	resp, err := sc.Do(req)
	if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events: %v %v", resp, err)
	}
	out := make(chan sseEvent, 64)
	go func() {
		defer resp.Body.Close()
		rd := bufio.NewScanner(resp.Body)
		rd.Buffer(make([]byte, 64<<10), 1<<20)
		name := ""
		for rd.Scan() {
			line := rd.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				var d map[string]any
				_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d)
				out <- sseEvent{name, d}
			}
		}
		close(out)
	}()
	return out
}

// waitFor reads events until one matches.
func waitFor(t *testing.T, ch <-chan sseEvent, what string, match func(sseEvent) bool) sseEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("stream closed before %s", what)
			}
			if match(ev) {
				return ev
			}
		case <-deadline:
			t.Fatalf("no %s", what)
		}
	}
}

func TestEventStream(t *testing.T) {
	h := newFakeHost(t, 10)
	e := newEnv(t, map[string]*fakeHost{"h": h}, envOpts{store: testStore(t)})
	eventually(t, "host polled", func() bool { s, _ := e.s.reg.get("h").state(); return s.Reachable })
	to, player := e.browser(uidTO), e.browser(uidPlayerA)
	toEvents, playerEvents := openStream(t, e, to, ""), openStream(t, e, player, "")
	for _, ch := range []<-chan sseEvent{toEvents, playerEvents} {
		snap := waitFor(t, ch, "snapshot", func(ev sseEvent) bool { return ev.name == "snapshot" })
		if len(snap.data["hosts"].([]any)) != 1 {
			t.Fatalf("snapshot: %v", snap.data)
		}
	}
	code, out := e.do(to, http.MethodPost, "/api/v1/lobbies", cupLobby(), nil)
	if code != 200 {
		t.Fatalf("create: %d %v", code, out)
	}
	key := out["lobby"].(map[string]any)["key"].(string)
	id := strings.TrimPrefix(key, "h/")
	isLobby := func(ev sseEvent) bool { return ev.name == "lobby" && ev.data["key"] == key }
	toLobby := waitFor(t, toEvents, "the organiser's lobby event", isLobby)
	pLobby := waitFor(t, playerEvents, "the player's lobby event", isLobby)
	if toLobby.data["host_record"] == nil || pLobby.data["host_record"] != nil || !strings.Contains(mustJSON(pLobby.data["you"]), "secret1") ||
		strings.Contains(mustJSON(pLobby.data["seats"]), "secret") {
		t.Fatalf("lobby events: organiser %v, player %v", toLobby.data, pLobby.data)
	}
	// The lobby server's own events reach the organiser as lobby_event, and the state change as a lobby event.
	eventually(t, "the service follows the lobby's events", func() bool { return h.emit(id, "probe", `{}`) })
	h.setStatus(id, map[string]any{"phase": "lobby", "seats": []any{map[string]any{"uid": uidPlayerA, "name": "A", "joined": true, "ready": "no"}}})
	h.emit(id, "joined", `{"uid":10,"name":"A"}`)
	ev := waitFor(t, toEvents, "the relayed joined event", func(ev sseEvent) bool { return ev.name == "lobby_event" && ev.data["event"] == "joined" })
	if ev.data["key"] != key || ev.data["data"].(map[string]any)["uid"] != float64(uidPlayerA) {
		t.Fatalf("lobby_event: %v", ev.data)
	}
	waitFor(t, playerEvents, "the player's view of the join", func(ev sseEvent) bool {
		if ev.name == "lobby_event" {
			t.Fatalf("a player got a lobby_event: %v", ev.data)
		}
		return isLobby(ev) && strings.Contains(mustJSON(ev.data["status"]), `"joined":true`)
	})
	// A stream for one lobby only; then the lobby goes and the stream says so.
	one := openStream(t, e, to, "?lobby="+key)
	snap := waitFor(t, one, "snapshot", func(ev sseEvent) bool { return ev.name == "snapshot" })
	if len(snap.data["lobbies"].([]any)) != 1 {
		t.Fatalf("one lobby's snapshot: %v", snap.data)
	}
	h.mu.Lock()
	h.lobbies = nil
	h.mu.Unlock()
	waitFor(t, one, "lobby_removed", func(ev sseEvent) bool { return ev.name == "lobby_removed" && ev.data["key"] == key })
	if n := e.s.hub.clientCount(); n != 3 {
		t.Fatalf("clients: %d", n)
	}
}
