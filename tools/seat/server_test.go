package seat

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"faf-main/tools/gpgnet"
	"faf-main/tools/journal"
)

// fakeGame is a game's end of a seat's GPGNet link.
type fakeGame struct {
	conn net.Conn
	in   *bufio.Reader
}

func dialSeat(t *testing.T, s *Seat) *fakeGame {
	t.Helper()
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(s.endpoint.Port()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &fakeGame{conn: conn, in: bufio.NewReader(conn)}
}

func (g *fakeGame) send(t *testing.T, m gpgnet.Message) {
	t.Helper()
	if err := gpgnet.WriteMessage(g.conn, m); err != nil {
		t.Fatal(err)
	}
}

// next is the seat's next message, or an empty one when none comes within d.
func (g *fakeGame) next(d time.Duration) gpgnet.Message {
	_ = g.conn.SetReadDeadline(time.Now().Add(d))
	m, err := gpgnet.ReadMessage(g.in)
	if err != nil {
		return gpgnet.Message{}
	}
	return m
}

type recorder struct {
	mu   sync.Mutex
	recs []journal.Record
}

func (r *recorder) add(rec journal.Record) {
	r.mu.Lock()
	r.recs = append(r.recs, rec)
	r.mu.Unlock()
}

func (r *recorder) all() []journal.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]journal.Record(nil), r.recs...)
}

func newServerSeat(t *testing.T, delivery string) (*Seat, *recorder) {
	t.Helper()
	rec := &recorder{}
	s, err := New(Config{UID: 1001, Name: "Seat One", Window: Window{Width: 800, Height: 600},
		Server: &ServerJoin{Address: "10.0.0.1:27050", Token: "token-of-seat-one", Delivery: delivery}}, nil, rec.add)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.endpoint.Close)
	return s, rec
}

// A game that announces ServerSession gets its own connection string in CreateLobby's place, and the journal keeps
// the token's tag, never the token.
func TestJoinServerInPlaceOfCreateLobby(t *testing.T) {
	s, rec := newServerSeat(t, DeliverGpgNet)
	g := dialSeat(t, s)
	g.send(t, gpgnet.New("PeerFeatures", fmt.Sprint(1<<featureServerBit), "abc1234"))
	g.send(t, gpgnet.New("GameState", "Idle"))
	m := g.next(5 * time.Second)
	if m.Command != "JoinServer" || m.Str(0) != "10.0.0.1:27050" || m.Str(1) != "token-of-seat-one" {
		t.Fatalf("got %v, want JoinServer with this seat's address and token", m)
	}
	if uid, ok := m.Int(2); !ok || uid != 1001 {
		t.Fatalf("JoinServer uid %v, want 1001", m.Args)
	}
	if extra := g.next(300 * time.Millisecond); extra.Command != "" {
		t.Fatalf("the seat sent %v too; a game on a game server gets no CreateLobby", extra)
	}
	sawTag := false
	for _, r := range rec.all() {
		text := fmt.Sprint(r.Command, r.Text, r.Args, r.Data)
		if strings.Contains(text, "token-of-seat-one") {
			t.Fatalf("journal record holds the token: %s", text)
		}
		if r.Kind == journal.GpgOut && r.Command == "JoinServer" && strings.Contains(text, TokenTag("token-of-seat-one")) {
			sawTag = true
		}
	}
	if !sawTag {
		t.Fatal("the journal has no JoinServer record with the token's tag")
	}
}

// A game that didn't announce ServerSession (another build) gets nothing: a launcher asks the announcement first.
func TestJoinServerNeedsTheAnnouncement(t *testing.T) {
	for _, mask := range []string{"", "16"} { // nothing announced; Rejoin only
		s, rec := newServerSeat(t, DeliverGpgNet)
		g := dialSeat(t, s)
		if mask != "" {
			g.send(t, gpgnet.New("PeerFeatures", mask, "abc1234"))
		}
		g.send(t, gpgnet.New("GameState", "Idle"))
		if m := g.next(500 * time.Millisecond); m.Command != "" {
			t.Fatalf("mask %q: the seat sent %v", mask, m)
		}
		warned := false
		for _, r := range rec.all() {
			warned = warned || (r.Kind == journal.Warn && strings.Contains(r.Text, "ServerSession"))
		}
		if !warned {
			t.Fatalf("mask %q: no warning in the journal", mask)
		}
	}
}

// With args delivery the connection string is on the game's command line and the seat answers Idle as an unchanged
// ICE adapter does (the game ignores that CreateLobby).
func TestArgsDelivery(t *testing.T) {
	s, _ := newServerSeat(t, DeliverArgs)
	line := strings.Join(s.cfg.GameArgs(1234), " ")
	if !strings.Contains(line, "/connectserver 10.0.0.1:27050 /servertoken token-of-seat-one /serveruid 1001") {
		t.Fatalf("args delivery: %s", line)
	}
	if !strings.Contains(line, "/gpgnetfeatures") || !strings.Contains(line, "/gpgnet 127.0.0.1:1234") {
		t.Fatalf("args delivery keeps /gpgnet and asks for the features: %s", line)
	}
	shown := strings.Join(RedactArgs(s.cfg.GameArgs(1234)), " ")
	if strings.Contains(shown, "token-of-seat-one") || !strings.Contains(shown, "/servertoken "+TokenTag("token-of-seat-one")) {
		t.Fatalf("redacted: %s", shown)
	}
	g := dialSeat(t, s)
	g.send(t, gpgnet.New("PeerFeatures", fmt.Sprint(1<<featureServerBit), "abc1234"))
	g.send(t, gpgnet.New("GameState", "Idle"))
	if m := g.next(5 * time.Second); m.Command != "CreateLobby" {
		t.Fatalf("got %v, want CreateLobby", m)
	}

	gp, _ := newServerSeat(t, DeliverGpgNet)
	if line := strings.Join(gp.cfg.GameArgs(1234), " "); strings.Contains(line, "token-of-seat-one") ||
		strings.Contains(line, "/connectserver") {
		t.Fatalf("gpgnet delivery puts nothing of the connection string on the command line: %s", line)
	}
}

func TestTokenTag(t *testing.T) {
	a, b := TokenTag("token-of-seat-one"), TokenTag("token-of-seat-two")
	if a == b || a != TokenTag("token-of-seat-one") || !strings.HasPrefix(a, "token:") || len(a) != len("token:")+12 {
		t.Fatalf("tags %q %q", a, b)
	}
}
