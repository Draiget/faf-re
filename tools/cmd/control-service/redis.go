package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// redisStore is the Store on Redis (6.2 or newer, for GETDEL), spoken in RESP2 over one TCP connection for commands
// and one per subscription. Every key gets the configured prefix; channels too.
type redisStore struct {
	addr, password string
	db             int
	prefix         string

	mu   sync.Mutex // one command at a time on conn
	conn net.Conn
	rd   *bufio.Reader
}

type redisError string

func (e redisError) Error() string { return "redis: " + string(e) }

func newRedisStore(ctx context.Context, addr, password string, db int, prefix string) (*redisStore, error) {
	r := &redisStore{addr: addr, password: password, db: db, prefix: prefix}
	if v, err := r.do(ctx, "PING"); err != nil {
		return nil, err
	} else if s, _ := v.(string); s != "PONG" {
		return nil, fmt.Errorf("redis at %s answered PING with %v", addr, v)
	}
	return r, nil
}

func (r *redisStore) Kind() string { return "redis" }

func (r *redisStore) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		err := r.conn.Close()
		r.conn = nil
		return err
	}
	return nil
}

// dial opens a connection and authenticates it.
func (r *redisStore) dial(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp", r.addr)
	if err != nil {
		return nil, nil, err
	}
	rd := bufio.NewReader(c)
	setup := [][]string{}
	if r.password != "" {
		setup = append(setup, []string{"AUTH", r.password})
	}
	if r.db != 0 {
		setup = append(setup, []string{"SELECT", strconv.Itoa(r.db)})
	}
	for _, cmd := range setup {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(encodeCommand(cmd)); err != nil {
			c.Close()
			return nil, nil, err
		}
		if _, err := readReply(rd); err != nil {
			c.Close()
			return nil, nil, fmt.Errorf("redis %s: %w", cmd[0], err)
		}
	}
	_ = c.SetDeadline(time.Time{})
	return c, rd, nil
}

func encodeCommand(args []string) []byte {
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		b.WriteString("$" + strconv.Itoa(len(a)) + "\r\n" + a + "\r\n")
	}
	return []byte(b.String())
}

// readReply reads one RESP2 reply: string (simple), redisError, int64, *string (bulk; nil for a null bulk) or []any.
func readReply(rd *bufio.Reader) (any, error) {
	line, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return nil, fmt.Errorf("redis: malformed reply %q", line)
	}
	kind, body := line[0], line[1:len(line)-2]
	switch kind {
	case '+':
		return body, nil
	case '-':
		return redisError(body), nil
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return (*string)(nil), nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(rd, buf); err != nil {
			return nil, err
		}
		s := string(buf[:n])
		return &s, nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return []any(nil), nil
		}
		out := make([]any, n)
		for i := range out {
			if out[i], err = readReply(rd); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("redis: unknown reply type %q", kind)
}

// do runs one command, dialing (again) when there is no connection; a broken connection is retried once.
func (r *redisStore) do(ctx context.Context, args ...string) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if r.conn == nil {
			c, rd, err := r.dial(ctx)
			if err != nil {
				return nil, err
			}
			r.conn, r.rd = c, rd
		}
		deadline := time.Now().Add(5 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = r.conn.SetDeadline(deadline)
		_, err := r.conn.Write(encodeCommand(args))
		var v any
		if err == nil {
			v, err = readReply(r.rd)
		}
		if err != nil {
			r.conn.Close()
			r.conn = nil
			if attempt == 0 && ctx.Err() == nil {
				continue
			}
			return nil, err
		}
		if e, ok := v.(redisError); ok {
			return nil, e
		}
		return v, nil
	}
}

func bulk(v any) (string, bool) {
	if s, ok := v.(*string); ok && s != nil {
		return *s, true
	}
	return "", false
}

func (r *redisStore) Get(ctx context.Context, key string) (string, bool, error) {
	v, err := r.do(ctx, "GET", r.prefix+key)
	if err != nil {
		return "", false, err
	}
	s, ok := bulk(v)
	return s, ok, nil
}

func (r *redisStore) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	args := []string{"SET", r.prefix + key, value}
	if ttl > 0 {
		args = append(args, "PX", strconv.FormatInt(max(ttl.Milliseconds(), 1), 10))
	}
	_, err := r.do(ctx, args...)
	return err
}

func (r *redisStore) Del(ctx context.Context, key string) error {
	_, err := r.do(ctx, "DEL", r.prefix+key)
	return err
}

func (r *redisStore) Take(ctx context.Context, key string) (string, bool, error) {
	v, err := r.do(ctx, "GETDEL", r.prefix+key)
	if err != nil {
		return "", false, err
	}
	s, ok := bulk(v)
	return s, ok, nil
}

// globEscape makes s match itself in a Redis pattern.
func globEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`*?[]\`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func (r *redisStore) Keys(ctx context.Context, prefix string) ([]string, error) {
	out := []string{}
	cursor := "0"
	pattern := globEscape(r.prefix+prefix) + "*"
	for {
		v, err := r.do(ctx, "SCAN", cursor, "MATCH", pattern, "COUNT", "500")
		if err != nil {
			return nil, err
		}
		arr, ok := v.([]any)
		if !ok || len(arr) != 2 {
			return nil, errors.New("redis: SCAN answered something else")
		}
		next, _ := bulk(arr[0])
		keys, _ := arr[1].([]any)
		for _, k := range keys {
			if s, ok := bulk(k); ok {
				out = append(out, strings.TrimPrefix(s, r.prefix))
			}
		}
		if next == "0" || next == "" {
			break
		}
		cursor = next
	}
	return out, nil
}

func (r *redisStore) Publish(ctx context.Context, channel, msg string) error {
	_, err := r.do(ctx, "PUBLISH", r.prefix+channel, msg)
	return err
}

// Subscribe keeps a connection of its own subscribed, dialing again after a failure (1 s apart) until ctx ends.
func (r *redisStore) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	out := make(chan string, 256)
	full := r.prefix + channel
	subscribe := func() (net.Conn, *bufio.Reader, error) {
		c, rd, err := r.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(encodeCommand([]string{"SUBSCRIBE", full})); err != nil {
			c.Close()
			return nil, nil, err
		}
		if _, err := readReply(rd); err != nil { // ["subscribe", channel, 1]
			c.Close()
			return nil, nil, err
		}
		_ = c.SetDeadline(time.Time{})
		return c, rd, nil
	}
	c, rd, err := subscribe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer close(out)
		for {
			done := make(chan struct{})
			go func(c net.Conn) {
				select {
				case <-ctx.Done():
					c.Close()
				case <-done:
				}
			}(c)
			for {
				v, err := readReply(rd)
				if err != nil {
					break
				}
				arr, ok := v.([]any)
				if !ok || len(arr) != 3 {
					continue
				}
				if kind, _ := bulk(arr[0]); kind != "message" {
					continue
				}
				if msg, ok := bulk(arr[2]); ok {
					select {
					case out <- msg:
					default: // a reader that doesn't keep up loses messages
					}
				}
			}
			close(done)
			c.Close()
			for {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				if c, rd, err = subscribe(); err == nil {
					break
				}
			}
		}
	}()
	return out, nil
}
