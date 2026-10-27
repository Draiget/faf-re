package netfuzz

import (
	"fmt"
	"math/rand"
	"sort"
)

// CraftedPacket is one datagram the generator will send, tagged with the
// reject/handler branch it is meant to exercise.
type CraftedPacket struct {
	Category string // attack family (see Categories)
	Name     string // specific case within the family
	Data     []byte // exact bytes to put on the wire
}

// GenOptions controls corpus generation.
type GenOptions struct {
	// Seed makes a run reproducible. Same seed, same corpus.
	Seed int64
	// RandomCount is how many fully random datagrams the "random" category
	// emits. Zero uses a default.
	RandomCount int
	// Categories selects attack families by name. Empty means all of them.
	Categories []string
}

// categoryFunc appends a family's packets to acc using rng for any fuzzed bytes.
type categoryFunc func(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket

// registry maps category name -> generator. Every family is grounded in a
// concrete validation branch in the C++ receive path.
var registry = map[string]categoryFunc{
	"short":      genShort,
	"length-lie": genLengthLie,
	"type-sweep": genTypeSweep,
	"connect":    genConnect,
	"answer":     genAnswer,
	"data":       genData,
	"ack":        genAck,
	"nat":        genNAT,
	"oversize":   genOversize,
	"random":     genRandom,
}

// Categories returns all known attack-family names, sorted.
func Categories() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Describe returns a one-line explanation of each category.
func Describe() map[string]string {
	return map[string]string{
		"short":      "datagrams below the 15-byte header floor (ReceiveData short-packet drop)",
		"length-lie": "valid header whose mPayloadLength disagrees with the datagram size (framing drop)",
		"type-sweep": "every type byte 0..255: known dispatch, unimplemented 2/3, unknown >=9",
		"connect":    "CONNECT (type 0): bad lengths, protocols, compression, obsolete/extreme times",
		"answer":     "ANSWER (type 1): bad lengths, wrong receiver nonce, bad compression",
		"data":       "DATA (type 4): sequence/expected/earlyMask window and shift edge cases",
		"ack":        "ACK/KEEPALIVE/GOODBYE (5/6/7): extreme expected-seq and earlyMask",
		"nat":        "NAT traversal (type 8): the mSize-1 payload slice, tiny and max sizes",
		"oversize":   "datagrams of 512 and beyond (recvfrom 512 cap)",
		"random":     "fully random datagrams of random length [0,1024]",
	}
}

// Generate builds the ordered corpus for the selected categories.
func Generate(opts GenOptions) ([]CraftedPacket, error) {
	rng := rand.New(rand.NewSource(opts.Seed))
	if opts.RandomCount <= 0 {
		opts.RandomCount = 256
	}

	want := opts.Categories
	if len(want) == 0 {
		want = Categories()
	}

	var acc []CraftedPacket
	for _, name := range want {
		fn, ok := registry[name]
		if !ok {
			return nil, fmt.Errorf("netfuzz: unknown category %q (have %v)", name, Categories())
		}
		if name == "random" {
			acc = genRandomN(rng, acc, opts.RandomCount)
			continue
		}
		acc = fn(rng, acc)
	}
	return acc, nil
}

// randBytes returns n random bytes from rng.
func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	_, _ = rng.Read(b)
	return b
}

// --- categories -----------------------------------------------------------

// genShort: anything shorter than the 15-byte header. ReceiveData logs and
// drops these ("ignoring short (%d bytes) packet"). Includes the 0-length
// datagram, which must not be mistaken for a NAT frame (the n>0 guard).
func genShort(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	for n := 0; n < HeaderSize; n++ {
		acc = append(acc, CraftedPacket{"short", fmt.Sprintf("zero-%d", n), make([]byte, n)})
		if n > 0 {
			acc = append(acc, CraftedPacket{"short", fmt.Sprintf("rand-%d", n), randBytes(rng, n)})
		}
	}
	return acc
}

// genLengthLie: a well-formed 15-byte header whose mPayloadLength does not
// match the real datagram length. ReceiveData computes expected =
// mPayloadLength + 15 and drops the frame when it differs ("payload length
// mismatch"). Type is PTData so the mismatch branch (not the unknown-type
// branch) is the one taken.
func genLengthLie(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	type lie struct {
		name    string
		claim   uint16
		payload int
	}
	lies := []lie{
		{"hdr-only-claim-1", 1, 0},
		{"hdr-only-claim-45", 45, 0},
		{"hdr-only-claim-497", 497, 0},
		{"hdr-only-claim-max", 0xFFFF, 0},
		{"payload-100-claim-0", 0, 100},
		{"payload-100-claim-500", 500, 100},
		{"payload-497-claim-max", 0xFFFF, 497},
		{"payload-1-claim-2", 2, 1},
	}
	for _, l := range lies {
		h := Header{Type: PTData, PayloadLength: l.claim}
		acc = append(acc, CraftedPacket{"length-lie", l.name, Frame(h, randBytes(rng, l.payload))})
	}
	return acc
}

// genTypeSweep: every possible type byte, honestly framed with a 1-byte
// payload (n=16). Exercises the whole dispatch switch: CONNECT (wrong size),
// the per-connection types (routed if a connection exists, else "unknown
// host"), the unimplemented 2/3, the NAT path, and every unknown type >= 9.
func genTypeSweep(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	for t := 0; t <= 0xFF; t++ {
		h := Header{Type: byte(t)}
		acc = append(acc, CraftedPacket{"type-sweep", fmt.Sprintf("type-%d", t), FrameHonest(h, randBytes(rng, 1))})
	}
	return acc
}

// genConnect: CONNECT frames. The connector requires size==60 and protocol==2;
// the connection's ProcessConnect then checks compression and the handshake
// time. Every frame here is honestly length-framed so it reaches ProcessConnect.
func genConnect(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	add := func(name string, body []byte) {
		h := Header{Type: PTConnect}
		acc = append(acc, CraftedPacket{"connect", name, FrameHonest(h, body)})
	}

	// Canonical, valid CONNECT (also primes a pending connection host-side).
	add("valid", ConnectBody(ProtoUDP, 1, CompNone, randBytes(rng, NonceSize)))

	// Protocol sweep at the right length/compression.
	for _, p := range []int32{ProtoNone, ProtoTCP, 3, -1, ProtoUDP} {
		add(fmt.Sprintf("proto-%d", p), ConnectBody(p, 2, CompNone, randBytes(rng, NonceSize)))
	}

	// Compression sweep (the handler rejects >= 2).
	for _, c := range []byte{CompNone, CompDeflate, 2, 0xFF} {
		add(fmt.Sprintf("comp-%d", c), ConnectBody(ProtoUDP, 3, c, randBytes(rng, NonceSize)))
	}

	// Handshake-time extremes -> obsolete-CONNECT branch (time <= mHandshakeTime).
	for _, tm := range []int64{0, -1, 1 << 62, -(1 << 62)} {
		add(fmt.Sprintf("time-%d", tm), ConnectBody(ProtoUDP, tm, CompNone, randBytes(rng, NonceSize)))
	}

	// Wrong body lengths -> ProcessConnect "wrong length CONNECT" (needs 60).
	for _, n := range []int{0, 15, ConnectBodySize - 1, ConnectBodySize + 1, MaxPayload} {
		body := make([]byte, n)
		if n >= 4 {
			body[0] = ProtoUDP // keep protocol plausible where it fits
		}
		add(fmt.Sprintf("len-%d", HeaderSize+n), body)
	}
	return acc
}

// genAnswer: ANSWER frames. Reaches ProcessAnswer only when the host already
// has a connection from our endpoint (prime a CONNECT first), where it checks
// size==92, the 32-byte receiver nonce, and compression.
func genAnswer(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	add := func(name string, body []byte) {
		h := Header{Type: PTAnswer}
		acc = append(acc, CraftedPacket{"answer", name, FrameHonest(h, body)})
	}

	add("valid-shape-rand-nonce", AnswerBody(ProtoUDP, 1<<40, CompNone, randBytes(rng, NonceSize), randBytes(rng, NonceSize)))
	add("zero-receiver-nonce", AnswerBody(ProtoUDP, 1<<40, CompNone, randBytes(rng, NonceSize), make([]byte, NonceSize)))

	for _, c := range []byte{CompDeflate, 2, 0xFF} {
		add(fmt.Sprintf("comp-%d", c), AnswerBody(ProtoUDP, 1<<40, c, randBytes(rng, NonceSize), randBytes(rng, NonceSize)))
	}
	for _, p := range []int32{ProtoNone, ProtoTCP, -1} {
		add(fmt.Sprintf("proto-%d", p), AnswerBody(p, 1<<40, CompNone, randBytes(rng, NonceSize), randBytes(rng, NonceSize)))
	}
	// Wrong lengths -> "wrong length ANSWER" (needs 92).
	for _, n := range []int{AnswerBodySize - 1, AnswerBodySize + 1, 0, ConnectBodySize} {
		add(fmt.Sprintf("len-%d", HeaderSize+n), make([]byte, n))
	}
	return acc
}

// seqEdges are the 16-bit sequence values that sit on the window boundaries the
// handlers compute with signed 16-bit arithmetic.
var seqEdges = []uint16{0, 1, 2, 31, 32, 33, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF}

// maskEdges exercise the early-ack bit test (idx = seqDelta-1; mask>>idx),
// including the guarded top bit and all-ones.
var maskEdges = []uint32{0, 1, 2, 0x8000_0000, 0x7FFF_FFFF, 0xFFFF_FFFF}

// genData: DATA frames across the sequence/expected/earlyMask edges. These feed
// ProcessAckInternal (the signed-16 "ack of data we haven't sent" check and the
// masked early-ack loop) and ProcessData's delta window (drop if <0, drop if
// >32, otherwise insert into the early set). Only reach the body with a primed
// connection.
func genData(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	payload := randBytes(rng, 8)
	for _, seq := range seqEdges {
		for _, exp := range []uint16{0, 1, 32, 0x7FFF, 0x8000, 0xFFFF} {
			h := Header{Type: PTData, Sequence: seq, ExpectedSequence: exp, EarlyMask: maskEdges[rng.Intn(len(maskEdges))]}
			name := fmt.Sprintf("seq-%d-exp-%d", seq, exp)
			acc = append(acc, CraftedPacket{"data", name, FrameHonest(h, payload)})
		}
	}
	// Dedicated mask sweep at a fixed, in-window sequence.
	for _, m := range maskEdges {
		h := Header{Type: PTData, Sequence: 1, ExpectedSequence: 0, EarlyMask: m}
		acc = append(acc, CraftedPacket{"data", fmt.Sprintf("mask-%08x", m), FrameHonest(h, payload)})
	}
	return acc
}

// genAck: ACK, KEEPALIVE and GOODBYE control frames (empty payload, n=15) with
// extreme expected-sequence and earlyMask values. All run through
// ProcessAckInternal; GOODBYE additionally drives the end-of-input/decompress
// teardown path.
func genAck(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	types := map[string]byte{"ack": PTAck, "keepalive": PTKeepAlive, "goodbye": PTGoodbye}
	names := []string{"ack", "keepalive", "goodbye"}
	for _, tn := range names {
		t := types[tn]
		for _, exp := range seqEdges {
			m := maskEdges[rng.Intn(len(maskEdges))]
			h := Header{Type: t, ExpectedSequence: exp, EarlyMask: m, Sequence: uint16(rng.Intn(0x10000))}
			acc = append(acc, CraftedPacket{"ack", fmt.Sprintf("%s-exp-%d", tn, exp), FrameHonest(h, nil)})
		}
	}
	// A couple of repeated GOODBYEs to re-enter the already-closed path.
	g := FrameHonest(Header{Type: PTGoodbye}, nil)
	acc = append(acc, CraftedPacket{"ack", "goodbye-repeat-1", g})
	acc = append(acc, CraftedPacket{"ack", "goodbye-repeat-2", g})
	return acc
}

// genNAT: NAT-traversal frames (type 8). ReceiveData queues these whole and
// Pull hands the provider payload+1 with length mSize-1, so the one-byte frame
// (length 0 after the slice) and the maximum-size frame are the interesting
// edges.
func genNAT(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	for _, extra := range []int{0, 1, 14, 59, MaxPayload, MaxPacketSize - 1} {
		d := make([]byte, 1+extra)
		d[0] = PTNATTraversal
		if extra > 0 {
			copy(d[1:], randBytes(rng, extra))
		}
		acc = append(acc, CraftedPacket{"nat", fmt.Sprintf("size-%d", len(d)), d})
	}
	return acc
}

// genOversize: datagrams at and past the 512-byte recvfrom cap. Each starts
// with a plausible DATA header so the truncated-to-512 remainder still parses
// as a frame.
func genOversize(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	for _, n := range []int{MaxPacketSize, MaxPacketSize + 1, 600, 1024, 2048} {
		h := Header{Type: PTData, PayloadLength: MaxPayload}
		d := Frame(h, randBytes(rng, n-HeaderSize))
		acc = append(acc, CraftedPacket{"oversize", fmt.Sprintf("size-%d", n), d})
	}
	return acc
}

// genRandomN: fully random datagrams of random length in [0,1024].
func genRandomN(rng *rand.Rand, acc []CraftedPacket, count int) []CraftedPacket {
	for i := 0; i < count; i++ {
		n := rng.Intn(1025)
		acc = append(acc, CraftedPacket{"random", fmt.Sprintf("r%d-len-%d", i, n), randBytes(rng, n)})
	}
	return acc
}

// genRandom is the registry stub; Generate special-cases "random" to pass the
// configured count.
func genRandom(rng *rand.Rand, acc []CraftedPacket) []CraftedPacket {
	return genRandomN(rng, acc, 256)
}
