package gpgnet

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	big := strings.Repeat("x", 200_000) // JsonStats-sized: above faf-pioneer's 64 KiB cap
	msgs := []Message{
		New("CreateLobby", 1, 14080, "Alpha", 1, 1),
		New("JoinGame", "127.0.0.1:14081", "Bravo", 2),
		New("GameState", "Idle"),
		New("JsonStats", big),
		New("SendNatPacket", "1.2.3.4:5", Data{0, 1, 2, 255}),
		New("Empty"),
	}
	var buf bytes.Buffer
	for _, m := range msgs {
		if err := WriteMessage(&buf, m); err != nil {
			t.Fatal(err)
		}
	}
	r := bufio.NewReader(&buf)
	for _, want := range msgs {
		got, err := ReadMessage(r)
		if err != nil {
			t.Fatalf("%s: %v", want.Command, err)
		}
		if got.String() != want.String() {
			t.Fatalf("got %s want %s", got, want)
		}
	}
}

// The layout the game writes: a known-good byte sequence for GameState "Idle".
func TestWireLayout(t *testing.T) {
	var want bytes.Buffer
	le := func(v int32) { _ = binary.Write(&want, binary.LittleEndian, v) }
	le(9)
	want.WriteString("GameState")
	le(1)
	want.WriteByte(1)
	le(4)
	want.WriteString("Idle")

	got, err := Encode(New("GameState", "Idle"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("got % x\nwant % x", got, want.Bytes())
	}
}

func TestRejectsGarbage(t *testing.T) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, int32(-5))
	if _, err := ReadMessage(bufio.NewReader(&buf)); err == nil {
		t.Fatal("negative length accepted")
	}
}
