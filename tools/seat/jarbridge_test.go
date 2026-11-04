package seat

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"faf-main/tools/gpgnet"
)

// A datagram crosses the bridge both ways, and the game sees the peer at one address.
func TestJarBridgePassesDatagrams(t *testing.T) {
	loop := net.IPv4(127, 0, 0, 1)
	game, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loop})
	if err != nil {
		t.Fatal(err)
	}
	defer game.Close()
	jar, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loop})
	if err != nil {
		t.Fatal(err)
	}
	defer jar.Close()
	gamePort := game.LocalAddr().(*net.UDPAddr).Port
	jarPort := jar.LocalAddr().(*net.UDPAddr).Port

	// The test's lobby socket is not the game's (one port on one address holds one).
	b := &jarBridge{bind: "127.0.0.1", peers: map[int]*net.UDPConn{}, shaper: newLinkShaper("")}
	lobby, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loop})
	if err != nil {
		t.Fatal(err)
	}
	lobbyPort := lobby.LocalAddr().(*net.UDPAddr).Port
	lobby.Close()
	if err := b.openLobby(lobbyPort); err != nil {
		t.Fatal(err)
	}
	defer b.lobby.Close()
	b.game = &net.UDPAddr{IP: loop, Port: gamePort}

	m := b.rewrite(gpgnet.New("JoinGame", "127.0.0.1:"+strconv.Itoa(jarPort), "Alpha", 1))
	if m.Args[1] != "Alpha" || m.Str(0) == "127.0.0.1:"+strconv.Itoa(jarPort) {
		t.Fatalf("rewritten JoinGame: %v", m)
	}
	peer, err := net.ResolveUDPAddr("udp4", m.Str(0))
	if err != nil {
		t.Fatal(err)
	}
	if again := b.rewrite(gpgnet.New("ConnectToPeer", "127.0.0.1:"+strconv.Itoa(jarPort), "Alpha", 1)); again.Str(0) != m.Str(0) {
		t.Fatalf("a second message for the peer gave another socket: %s, %s", m.Str(0), again.Str(0))
	}
	defer b.peers[jarPort].Close()

	read := func(c *net.UDPConn) (string, *net.UDPAddr) {
		buf := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return string(buf[:n]), from
	}

	// Game to jar, from the socket the game was told about.
	if _, err := game.WriteToUDP([]byte("to jar"), peer); err != nil {
		t.Fatal(err)
	}
	if text, _ := read(jar); text != "to jar" {
		t.Fatalf("the jar got %q", text)
	}
	// Jar to the game's lobby port: it arrives from the peer's socket.
	if _, err := jar.WriteToUDP([]byte("to game"), &net.UDPAddr{IP: loop, Port: lobbyPort}); err != nil {
		t.Fatal(err)
	}
	text, from := read(game)
	if text != "to game" || from.Port != peer.Port {
		t.Fatalf("the game got %q from %v, want it from %v", text, from, peer)
	}
}

func TestLinkShaperReadsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shaping.txt")
	s := newLinkShaper(path)
	if _, pass := s.roll(); !pass {
		t.Fatal("no file: nothing is shaped")
	}
	if err := os.WriteFile(path, []byte("25000 0 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.nextRead = time.Time{}
	if delay, pass := s.roll(); !pass || delay != 25*time.Millisecond {
		t.Fatalf("latency: %v %v", delay, pass)
	}
	if err := os.WriteFile(path, []byte("0 0 0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.nextRead = time.Time{}
	if _, pass := s.roll(); pass {
		t.Fatal("a blocked link passed a datagram")
	}
}
