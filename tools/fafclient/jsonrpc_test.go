package fafclient

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadFrameMatchesJavaReader(t *testing.T) {
	in := "{\"a\":{\"b\":1}}\n{\"c\":[{}]}\n"
	r := bufio.NewReader(strings.NewReader(in))
	f1, err := ReadFrame(r)
	if err != nil || f1.Text != `{"a":{"b":1}}` {
		t.Fatalf("first frame %q, %v", f1.Text, err)
	}
	// The newline println left behind belongs to the next frame, as in Java.
	f2, err := ReadFrame(r)
	if err != nil || f2.Text != "\n{\"c\":[{}]}" {
		t.Fatalf("second frame %q, %v", f2.Text, err)
	}
	if _, err := ReadFrame(r); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestReadFrameBraceInStringSplitsLikeJava(t *testing.T) {
	// The Java reader does not track strings: "}" inside a string ends the
	// frame early. ReadFrame must do the same so tests catch such writers.
	r := bufio.NewReader(strings.NewReader(`{"login":"a}b"}`))
	f, err := ReadFrame(r)
	if err != nil || f.Text != `{"login":"a}` {
		t.Fatalf("frame %q, %v", f.Text, err)
	}
}

func TestReadFrameFlagsNonASCII(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(`{"login":"Ж"}`))
	f, err := ReadFrame(r)
	if err != nil || !f.NonASCII {
		t.Fatalf("frame %q nonASCII=%v, %v", f.Text, f.NonASCII, err)
	}
}

func TestCallRespondRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	client, server := NewPeer(a, nil), NewPeer(b, nil)
	go func() {
		_ = server.Serve(b, func(m Message) {
			if m.Method == "joinGame" && m.ID != nil {
				var login string
				_ = json.Unmarshal(m.Params[0], &login)
				_ = server.Respond(*m.ID, login)
			}
		})
	}()
	go func() { _ = client.Serve(a, func(Message) {}) }()
	ch, err := client.Call("joinGame", "player1", 101)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-ch:
		if string(m.Result) != `"player1"` {
			t.Fatalf("result %s", m.Result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no response")
	}
}
