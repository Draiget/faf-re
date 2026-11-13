package main

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store is the service's cache: sessions, sign-in states, the hosts' and lobbies' live state, and the channel the
// state changes go out on. Redis (redisStore) when the service runs with --redis, else memStore: the same interface,
// so the service runs without Redis.
type Store interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error // ttl 0: no expiry
	Del(ctx context.Context, key string) error
	// Take reads and deletes a key in one step (a one-time sign-in state).
	Take(ctx context.Context, key string) (string, bool, error)
	// Keys lists the keys starting with prefix.
	Keys(ctx context.Context, prefix string) ([]string, error)
	Publish(ctx context.Context, channel, msg string) error
	// Subscribe delivers the channel's messages until ctx ends; the channel then closes.
	Subscribe(ctx context.Context, channel string) (<-chan string, error)
	Kind() string
	Close() error
}

type memEntry struct {
	value   string
	expires time.Time // zero: never
}

type memStore struct {
	mu   sync.Mutex
	data map[string]memEntry
	subs map[string]map[chan string]bool
}

func newMemStore() *memStore {
	return &memStore{data: map[string]memEntry{}, subs: map[string]map[chan string]bool{}}
}

func (m *memStore) Kind() string { return "memory" }
func (m *memStore) Close() error { return nil }

// live returns the entry if it hasn't expired; the caller holds mu.
func (m *memStore) live(key string) (memEntry, bool) {
	e, ok := m.data[key]
	if ok && !e.expires.IsZero() && time.Now().After(e.expires) {
		delete(m.data, key)
		return memEntry{}, false
	}
	return e, ok
}

func (m *memStore) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	return e.value, ok, nil
}

func (m *memStore) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := memEntry{value: value}
	if ttl > 0 {
		e.expires = time.Now().Add(ttl)
	}
	m.data[key] = e
	return nil
}

func (m *memStore) Del(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memStore) Take(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	delete(m.data, key)
	return e.value, ok, nil
}

func (m *memStore) Keys(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			if _, ok := m.live(k); ok {
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memStore) Publish(_ context.Context, channel, msg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for ch := range m.subs[channel] {
		select {
		case ch <- msg:
		default: // a subscriber that doesn't keep up loses messages, as with Redis' output buffer limit
		}
	}
	return nil
}

func (m *memStore) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	ch := make(chan string, 256)
	m.mu.Lock()
	if m.subs[channel] == nil {
		m.subs[channel] = map[chan string]bool{}
	}
	m.subs[channel][ch] = true
	m.mu.Unlock()
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		delete(m.subs[channel], ch)
		close(ch)
		m.mu.Unlock()
	}()
	return ch, nil
}
