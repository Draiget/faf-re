// Package bus is mpemu's in-process message queue, standing in for the
// RabbitMQ exchange behind faf-icebreaker and carrying the hub's control
// traffic. Every key owns a mailbox. Messages published to a mailbox nobody
// is listening on yet are held and delivered when someone subscribes, so a
// peer that opens its stream a little late still sees what was sent to it.
package bus

import (
	"context"
	"sync"
)

// MaxPending bounds one mailbox; the oldest message is dropped beyond it.
const MaxPending = 1024

type entry struct {
	id      uint64
	payload []byte
}

type mailbox struct {
	mu         sync.Mutex
	queue      []entry
	nextID     uint64
	dropped    int
	generation int
	changed    chan struct{} // closed and replaced on every change
}

func (m *mailbox) signalLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

// Bus is safe for concurrent use.
type Bus struct {
	mu    sync.Mutex
	boxes map[string]*mailbox
}

// New returns an empty bus.
func New() *Bus { return &Bus{boxes: make(map[string]*mailbox)} }

func (b *Bus) box(key string) *mailbox {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.boxes[key]
	if m == nil {
		m = &mailbox{changed: make(chan struct{})}
		b.boxes[key] = m
	}
	return m
}

// Publish queues payload for one mailbox.
func (b *Bus) Publish(key string, payload []byte) {
	m := b.box(key)
	m.mu.Lock()
	m.nextID++
	m.queue = append(m.queue, entry{id: m.nextID, payload: payload})
	if len(m.queue) > MaxPending {
		m.queue = m.queue[1:]
		m.dropped++
	}
	m.signalLocked()
	m.mu.Unlock()
}

// Pending reports how many messages wait in a mailbox, and how many were dropped.
func (b *Bus) Pending(key string) (pending, dropped int) {
	m := b.box(key)
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.queue), m.dropped
}

// Subscribe delivers a mailbox's messages to deliver until ctx ends or a
// newer subscription for the same key takes over (a reconnecting stream).
// A message leaves the mailbox only once deliver has returned nil for it, so
// a stream that breaks mid-write loses nothing.
func (b *Bus) Subscribe(ctx context.Context, key string, deliver func([]byte) error) {
	m := b.box(key)
	m.mu.Lock()
	m.generation++
	gen := m.generation
	m.signalLocked() // an older subscriber wakes up and sees it was replaced
	m.mu.Unlock()

	for {
		m.mu.Lock()
		if m.generation != gen {
			m.mu.Unlock()
			return
		}
		var next entry
		ok := len(m.queue) > 0
		if ok {
			next = m.queue[0]
		}
		changed := m.changed
		m.mu.Unlock()

		if ok {
			if err := deliver(next.payload); err != nil {
				return
			}
			m.mu.Lock()
			if len(m.queue) > 0 && m.queue[0].id == next.id {
				m.queue = m.queue[1:]
			}
			m.mu.Unlock()
			continue
		}

		select {
		case <-changed:
		case <-ctx.Done():
			return
		}
	}
}
