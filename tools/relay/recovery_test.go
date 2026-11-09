package relay

import (
	"testing"
	"time"
)

func dataPacket(seq uint16) []byte {
	p := make([]byte, gameHeaderSize+4)
	p[0] = gameTypeData
	p[9], p[10] = byte(seq), byte(seq>>8)
	return p
}

func TestRecoveryTimesFromFirstDrop(t *testing.T) {
	var r recovery
	t0 := time.Unix(100, 0)
	r.onDrop(dataPacket(300), t0)
	r.onDrop(dataPacket(300), t0.Add(100*time.Millisecond)) // the resend is dropped too
	r.onPass(dataPacket(301), t0.Add(110*time.Millisecond)) // never dropped: not a sample
	r.onPass(dataPacket(300), t0.Add(250*time.Millisecond))
	r.onPass(dataPacket(300), t0.Add(260*time.Millisecond)) // a duplicate after recovery
	ack := dataPacket(7)
	ack[0] = 5 // not DATA
	r.onDrop(ack, t0)
	r.onPass(ack, t0.Add(time.Second))
	n, median, p90 := r.summary()
	if n != 1 || median != 250 || p90 != 250 {
		t.Fatalf("got n=%d median=%v p90=%v, want 1 sample of 250 ms", n, median, p90)
	}
}
