package bus

import (
	"context"
	"testing"
	"time"
)

func collect(ctx context.Context, b *Bus, key string, n int) <-chan []string {
	out := make(chan []string, 1)
	go func() {
		var got []string
		sub, cancel := context.WithCancel(ctx)
		defer cancel()
		b.Subscribe(sub, key, func(p []byte) error {
			got = append(got, string(p))
			if len(got) == n {
				cancel()
			}
			return nil
		})
		out <- got
	}()
	return out
}

func TestBuffersUntilSubscribed(t *testing.T) {
	b := New()
	b.Publish("g1/u7", []byte("a"))
	b.Publish("g1/u7", []byte("b"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := <-collect(ctx, b, "g1/u7", 3)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		// the third message never comes; ctx ends the subscription
		t.Fatalf("got %v", got)
	}
}

func TestLiveDeliveryAndReplacement(t *testing.T) {
	b := New()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	first := make(chan string, 8)
	go b.Subscribe(ctx, "g1/u3", func(p []byte) error { first <- string(p); return nil })
	time.Sleep(20 * time.Millisecond)
	b.Publish("g1/u3", []byte("one"))
	if v := <-first; v != "one" {
		t.Fatalf("got %q", v)
	}

	// A reconnecting stream takes over; the old one must stop receiving.
	second := collect(ctx, b, "g1/u3", 1)
	time.Sleep(20 * time.Millisecond)
	b.Publish("g1/u3", []byte("two"))
	if got := <-second; len(got) != 1 || got[0] != "two" {
		t.Fatalf("replacement got %v", got)
	}
	select {
	case v := <-first:
		t.Fatalf("replaced subscriber still received %q", v)
	case <-time.After(50 * time.Millisecond):
	}
}
