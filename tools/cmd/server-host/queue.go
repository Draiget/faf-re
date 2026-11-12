package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// The queue: lobbies that don't fit now wait, first in first out per side: the operator's (lobbies made with
// "queue": true) and the pool's (players' requests). Whenever a lobby ends, the pool changes, or every few seconds
// (memory and load change too), the host starts the first queued item of each side that fits, and again until
// none does.

// QueueItem is one waiting lobby.
type QueueItem struct {
	ID         string   `json:"id"`
	Side       string   `json:"side"` // operator or pool
	Kind       string   `json:"kind"` // tournament or custom
	Name       string   `json:"name"`
	Player     *string  `json:"player"`  // the requesting player, for a request
	Request    *string  `json:"request"` // the request's id
	Map        LobbyMap `json:"map"`
	Seats      int      `json:"seats"`
	Estimate   Estimate `json:"estimate"`
	Position   int      `json:"position"`    // 1 is next, per side
	WaitingFor string   `json:"waiting_for"` // games, cores, memory, network or ports; "" when it fits and starts next
	Created    string   `json:"created"`

	req       CreateRequest
	requestID string
	created   time.Time
	fresh     bool // a request not yet tried: if the first try starts it, it never waited (no queued_at)
}

var errNoQueueItem = errors.New("no such queued item")

// kick asks the queue loop to try the queue now.
func (m *manager) kick() {
	select {
	case m.kickCh <- struct{}{}:
	default:
	}
}

// runQueue tries the queue whenever kicked and every 5 s, and forgets old requests.
func (m *manager) runQueue(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-m.kickCh:
		case <-t.C:
			m.pruneRequests(time.Now())
		}
		m.pump()
	}
}

// enqueueLocked puts a lobby request at the end of its side's queue; the caller holds pumpMu.
func (m *manager) enqueueLocked(req CreateRequest, side, requestID, player string) (*QueueItem, int, error) {
	c := req.clone()
	mp, err := m.validate(&c)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if _, err := parseCPUs(req.CPUs); err != nil {
		return nil, http.StatusBadRequest, err
	}
	now := time.Now().UTC()
	name := c.Name
	if name == "" {
		name = mp.Name
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	q := &QueueItem{ID: "q" + strconv.Itoa(m.nextQueue), Side: side, Kind: c.Kind, Name: name, Map: LobbyMap{mp.ID, mp.Name, mp.KM, mp.Players},
		Seats: len(c.Seats), Estimate: estimateFor(len(c.Seats), mp.KM), Created: now.Format(time.RFC3339), req: req.clone(), requestID: requestID, created: now}
	if player != "" {
		p := player
		q.Player = &p
	}
	if requestID != "" {
		r := requestID
		q.Request = &r
		q.fresh = true
	}
	m.nextQueue++
	m.queue = append(m.queue, q)
	return q, http.StatusOK, nil
}

// positionLocked is an item's place in its side's queue (1 first), 0 if it isn't queued; the caller holds mu.
func (m *manager) positionLocked(id string) int {
	pos := map[string]int{}
	for _, q := range m.queue {
		pos[q.Side]++
		if q.ID == id {
			return pos[q.Side]
		}
	}
	return 0
}

// removeLocked takes an item out of the queue; the caller holds mu.
func (m *manager) removeLocked(id string) *QueueItem {
	for i, q := range m.queue {
		if q.ID == id {
			m.queue = append(m.queue[:i:i], m.queue[i+1:]...)
			return q
		}
	}
	return nil
}

func (q *QueueItem) need() need {
	n := need{side: q.Side, players: q.Seats, km: q.Map.KM, cores: q.req.Cores, force: q.req.Force, ports: 1}
	if len(q.req.Observers) > 0 {
		n.ports = 2
	}
	n.cpus, _ = parseCPUs(q.req.CPUs)
	return n
}

// listQueue is both queues in order, each item with its position and what it waits for now.
func (m *manager) listQueue() []QueueItem {
	m.mu.Lock()
	items := make([]QueueItem, 0, len(m.queue))
	for _, q := range m.queue {
		c := *q
		c.Position = m.positionLocked(q.ID)
		items = append(items, c)
	}
	m.mu.Unlock()
	machines := map[string]*machine{}
	for i := range items {
		side := items[i].Side
		if machines[side] == nil {
			machines[side] = m.machineFor(side)
		}
		_, items[i].WaitingFor, _, _ = m.fit(machines[side], items[i].need())
	}
	return items
}

func (m *manager) queueItem(id string) (QueueItem, bool) {
	for _, q := range m.listQueue() {
		if q.ID == id {
			return q, true
		}
	}
	return QueueItem{}, false
}

// pump starts what fits from the queue.
func (m *manager) pump() []string {
	m.pumpMu.Lock()
	defer m.pumpMu.Unlock()
	return m.pumpLocked()
}

// pumpLocked starts the first item of each side that fits, again until none does; an item that can't start for
// another reason (its map is gone, the server didn't start) leaves the queue, and its request is refused. The caller
// holds pumpMu.
func (m *manager) pumpLocked() []string {
	var started []string
	for {
		m.mu.Lock()
		stopping := m.stopping
		m.mu.Unlock()
		if stopping {
			return started
		}
		progressed := false
		for _, side := range []string{"operator", "pool"} {
			m.mu.Lock()
			var items []*QueueItem
			for _, q := range m.queue {
				if q.Side == side {
					items = append(items, q)
				}
			}
			m.mu.Unlock()
			if len(items) == 0 {
				continue
			}
			mc := m.machineFor(side)
			for _, q := range items {
				if _, waiting, _, err := m.fit(mc, q.need()); err != nil && waiting != "" {
					continue
				}
				o := startOpts{side: side, request: q.requestID, queuedAt: q.created}
				if q.fresh {
					o.queuedAt = time.Time{}
				}
				l, _, waiting, err := m.start(q.req.clone(), o)
				if err != nil && waiting != "" {
					continue // taken meanwhile; it waits on
				}
				m.mu.Lock()
				m.removeLocked(q.ID)
				r := m.requests[q.requestID]
				if err != nil {
					if r != nil {
						r.setEnded("refused", err.Error())
					}
				} else if r != nil {
					r.lobbyID, r.state = l.ID, "started"
				}
				m.mu.Unlock()
				switch {
				case err != nil:
					log.Printf("queued %s (%s) not started: %v", q.ID, q.Name, err)
				case q.fresh: // a request that started at once; submitRequest says so
					started = append(started, l.ID)
				default:
					log.Printf("queued %s started as lobby %s: %s on CPUs %v, port %d, after %s", q.ID, l.ID, l.Map.Name, l.CPUs, l.Port,
						time.Since(q.created).Round(time.Second))
					started = append(started, l.ID)
				}
				progressed = true
				break
			}
		}
		if !progressed {
			return started
		}
	}
}

// createOrQueue starts an operator's lobby, or with "queue": true queues it when it doesn't fit for want of capacity.
func (m *manager) createOrQueue(req CreateRequest) (*Lobby, *QueueItem, int, error) {
	l, code, waiting, err := m.start(req.clone(), startOpts{side: "operator"})
	if err == nil || waiting == "" || !req.Queue {
		return l, nil, code, err
	}
	m.pumpMu.Lock()
	q, code, err := m.enqueueLocked(req, "operator", "", "")
	m.pumpMu.Unlock()
	if err != nil {
		return nil, nil, code, err
	}
	log.Printf("queued %s (%s): it waits for %s", q.ID, q.Name, waiting)
	m.kick()
	if item, ok := m.queueItem(q.ID); ok {
		return nil, &item, http.StatusAccepted, nil
	}
	// Started meanwhile by the queue loop.
	return nil, q, http.StatusAccepted, nil
}

// cancelQueued takes an item out of the queue (the operator's cancel); its request is cancelled.
func (m *manager) cancelQueued(id string) error {
	m.pumpMu.Lock()
	defer m.pumpMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	q := m.removeLocked(id)
	if q == nil {
		return errNoQueueItem
	}
	if r := m.requests[q.requestID]; r != nil {
		r.setEnded("cancelled", "cancelled by the operator")
	}
	m.kick() // a later item may fit now that it waits behind nobody
	return nil
}

// moveUp moves an item one place earlier in its side's queue.
func (m *manager) moveUp(id string) error {
	m.pumpMu.Lock()
	defer m.pumpMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, q := range m.queue {
		if q.ID != id {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			if m.queue[j].Side == q.Side {
				m.queue[i], m.queue[j] = m.queue[j], m.queue[i]
				break
			}
		}
		m.kick()
		return nil
	}
	return fmt.Errorf("%w: %s", errNoQueueItem, id)
}
