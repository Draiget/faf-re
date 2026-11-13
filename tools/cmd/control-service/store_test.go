package main

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// testStore is Redis when CONTROL_TEST_REDIS names one (host:port; each test gets its own key prefix), else memory.
func testStore(t *testing.T) Store {
	t.Helper()
	addr := os.Getenv("CONTROL_TEST_REDIS")
	if addr == "" {
		return newMemStore()
	}
	prefix := "faf-control-test:" + randomToken(6) + ":"
	r, err := newRedisStore(context.Background(), addr, os.Getenv("CONTROL_TEST_REDIS_PASSWORD"), 0, prefix)
	if err != nil {
		t.Fatalf("CONTROL_TEST_REDIS=%s: %v", addr, err)
	}
	t.Cleanup(func() {
		keys, _ := r.Keys(context.Background(), "")
		for _, k := range keys {
			_ = r.Del(context.Background(), k)
		}
		r.Close()
	})
	return r
}

func TestStoreContract(t *testing.T) {
	s := testStore(t)
	t.Logf("store: %s", s.Kind())
	ctx := t.Context()
	if _, ok, err := s.Get(ctx, "a"); ok || err != nil {
		t.Fatalf("missing key: %v %v", ok, err)
	}
	if err := s.Set(ctx, "lobby:h/1", `{"x":1}`, 0); err != nil {
		t.Fatal(err)
	}
	_ = s.Set(ctx, "lobby:h/2", "two", time.Minute)
	_ = s.Set(ctx, "lobbyx", "not a lobby", 0)
	_ = s.Set(ctx, "short", "gone soon", 50*time.Millisecond)
	if v, ok, _ := s.Get(ctx, "lobby:h/1"); !ok || v != `{"x":1}` {
		t.Fatalf("get: %q %v", v, ok)
	}
	keys, err := s.Keys(ctx, "lobby:")
	if err != nil || len(keys) != 2 || !strings.HasPrefix(keys[0], "lobby:h/") {
		t.Fatalf("keys: %v %v", keys, err)
	}
	time.Sleep(120 * time.Millisecond)
	if _, ok, _ := s.Get(ctx, "short"); ok {
		t.Fatal("expired key still there")
	}
	if v, ok, _ := s.Take(ctx, "lobby:h/2"); !ok || v != "two" {
		t.Fatalf("take: %q %v", v, ok)
	}
	if _, ok, _ := s.Take(ctx, "lobby:h/2"); ok {
		t.Fatal("take twice")
	}
	_ = s.Del(ctx, "lobby:h/1")
	if _, ok, _ := s.Get(ctx, "lobby:h/1"); ok {
		t.Fatal("deleted key still there")
	}
	sctx, cancel := context.WithCancel(ctx)
	ch, err := s.Subscribe(sctx, "chan")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	for _, m := range []string{"one", "two\nlines", ""} {
		if err := s.Publish(ctx, "chan", m); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Publish(ctx, "other", "not for us")
	for _, want := range []string{"one", "two\nlines", ""} {
		select {
		case got := <-ch:
			if got != want {
				t.Fatalf("message %q, want %q", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no message %q", want)
		}
	}
	cancel()
	for range ch { // closes after ctx ends
	}
}

func TestRESPReplies(t *testing.T) {
	in := "+OK\r\n-ERR wrong\r\n:42\r\n$5\r\nhe\r\no\r\n$-1\r\n*2\r\n$1\r\n0\r\n*1\r\n$3\r\nkey\r\n"
	rd := bufio.NewReader(strings.NewReader(in))
	want := []string{"OK", "redis: ERR wrong", "42", "he\r\no", "<nil>", "[0 [key]]"}
	for i, w := range want {
		v, err := readReply(rd)
		if err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
		got := ""
		switch x := v.(type) {
		case string:
			got = x
		case redisError:
			got = x.Error()
		case int64:
			got = "42"
		case *string:
			if x == nil {
				got = "<nil>"
			} else {
				got = *x
			}
		case []any:
			got = "[" + deref(x[0]) + " [" + deref(x[1].([]any)[0]) + "]]"
		}
		if got != w {
			t.Errorf("reply %d = %q, want %q", i, got, w)
		}
	}
	if string(encodeCommand([]string{"SET", "k", "a b"})) != "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$3\r\na b\r\n" {
		t.Fatal("command encoding")
	}
	if globEscape(`a*b?[c]\`) != `a\*b\?\[c\]\\` {
		t.Fatal("glob escape")
	}
}

func deref(v any) string {
	s, _ := bulk(v)
	return s
}
