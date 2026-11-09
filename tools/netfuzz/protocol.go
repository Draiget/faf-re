// Package netfuzz plays a hostile UDP peer against a Forged Alliance (Moho
// engine) lobby host. It crafts datagrams exactly the way the engine's own
// transport frames them -- the 15-byte SNetPacketHeader followed by up to 497
// payload bytes -- and then deliberately breaks every field the receive path
// validates, so a run drives the host's parser through each of its reject
// branches and handler state transitions at runtime.
//
// The wire format is derived straight from the C++ source, which is the
// authority:
//
//   - src/moho/net/SNetPacket.h / .cpp         (header + CONNECT/ANSWER bodies)
//   - src/moho/net/NetTransportEnums.h         (EPacketType, protocol/compression)
//   - src/moho/net/CNetUDPConnector.cpp        (ReceiveData/ProcessConnect framing)
//   - src/moho/net/CNetUDPConnection.cpp       (per-connection handlers)
//
// The engine runs on 32-bit x86, so every multi-byte field is little-endian
// and the structs are packed with #pragma pack(1); the encoders below match
// that layout byte for byte.
//
// This is a defensive robustness tool: it exercises the hardening that keeps a
// malicious or buggy peer from crashing the host. It only sends UDP datagrams
// to an address the operator names; it never touches the game process.
package netfuzz

import "encoding/binary"

// Wire sizes, from SNetPacket.h.
const (
	// HeaderSize is sizeof(SNetPacketHeader): the 15-byte transport header on
	// every non-NAT frame.
	HeaderSize = 15
	// MaxPacketSize is kPacketMaxSize: recvfrom() in ReceiveData reads at most
	// this many bytes (512) per datagram.
	MaxPacketSize = 512
	// MaxPayload is kNetPacketMaxPayload == 512 - 15 == 497.
	MaxPayload = MaxPacketSize - HeaderSize

	// ConnectBodySize is sizeof(SPacketBodyConnect) == 45.
	ConnectBodySize = 45
	// AnswerBodySize is sizeof(SPacketBodyAnswer) == 77.
	AnswerBodySize = 77
	// ConnectPacketSize is the only length ProcessConnect accepts: 15 + 45 == 60.
	ConnectPacketSize = HeaderSize + ConnectBodySize
	// AnswerPacketSize is the only length ProcessAnswer accepts: 15 + 77 == 92.
	AnswerPacketSize = HeaderSize + AnswerBodySize

	// NonceSize is the length of the opaque handshake nonce blobs.
	NonceSize = 32
)

// EPacketType values, from NetTransportEnums.h. The receive path treats
// anything < PTNumTypes as a known type (dispatched or explicitly
// "unimplemented") and anything >= PTNumTypes as an unknown type it drops.
const (
	PTConnect      = 0
	PTAnswer       = 1
	PTResetSerial  = 2 // recognized, unimplemented in the current FA path
	PTSerialReset  = 3 // recognized, unimplemented in the current FA path
	PTData         = 4
	PTAck          = 5
	PTKeepAlive    = 6
	PTGoodbye      = 7
	PTNATTraversal = 8
	PTNumTypes     = 9
)

// Protocol tag values, from ENetProtocolType. ProcessConnect/ProcessAnswer
// require ProtoUDP; everything else is rejected.
const (
	ProtoNone = 0
	ProtoTCP  = 1
	ProtoUDP  = 2
)

// Compression methods, from ENetCompressionMethod. The handlers reject any
// value >= CompDeflate+1 (i.e. >= 2).
const (
	CompNone    = 0
	CompDeflate = 1
)

// Header mirrors moho::SNetPacketHeader (packed, little-endian).
//
//	EPacketType mType;                 // +0  (1)
//	uint32_t    mEarlyMask;            // +1  (4)
//	uint16_t    mSerialNumber;         // +5  (2)
//	uint16_t    mInResponseTo;         // +7  (2)
//	uint16_t    mSequenceNumber;       // +9  (2)
//	uint16_t    mExpectedSequenceNumber;// +11 (2)
//	uint16_t    mPayloadLength;        // +13 (2)
type Header struct {
	Type             byte
	EarlyMask        uint32
	Serial           uint16
	InResponseTo     uint16
	Sequence         uint16
	ExpectedSequence uint16
	// PayloadLength is the wire field. ReceiveData rejects a datagram unless
	// its total length equals PayloadLength + 15, so leaving this inconsistent
	// with the actual payload is exactly how the "payload length mismatch"
	// branch is reached.
	PayloadLength uint16
}

// Marshal serializes the header into its 15 wire bytes.
func (h Header) Marshal() []byte {
	b := make([]byte, HeaderSize)
	b[0] = h.Type
	binary.LittleEndian.PutUint32(b[1:5], h.EarlyMask)
	binary.LittleEndian.PutUint16(b[5:7], h.Serial)
	binary.LittleEndian.PutUint16(b[7:9], h.InResponseTo)
	binary.LittleEndian.PutUint16(b[9:11], h.Sequence)
	binary.LittleEndian.PutUint16(b[11:13], h.ExpectedSequence)
	binary.LittleEndian.PutUint16(b[13:15], h.PayloadLength)
	return b
}

// Frame concatenates a header and payload into one datagram. It does NOT touch
// PayloadLength: the caller decides whether the frame is honestly sized (set
// h.PayloadLength = len(payload)) or deliberately lying.
func Frame(h Header, payload []byte) []byte {
	out := h.Marshal()
	return append(out, payload...)
}

// FrameHonest frames header+payload with PayloadLength set to match the
// payload, so the datagram passes ReceiveData's length check and reaches the
// type's handler.
func FrameHonest(h Header, payload []byte) []byte {
	h.PayloadLength = uint16(len(payload))
	return Frame(h, payload)
}

// ConnectBody encodes an SPacketBodyConnect (45 bytes):
//
//	ENetProtocolType     protocol;      // +0  int32
//	int64_t              time;          // +4
//	ENetCompressionMethod comp;         // +12 uint8
//	char                 senderNonce[32];// +13
//
// nonce is truncated or zero-padded to 32 bytes.
func ConnectBody(protocol int32, t int64, comp byte, nonce []byte) []byte {
	b := make([]byte, ConnectBodySize)
	binary.LittleEndian.PutUint32(b[0:4], uint32(protocol))
	binary.LittleEndian.PutUint64(b[4:12], uint64(t))
	b[12] = comp
	copyFixed(b[13:45], nonce)
	return b
}

// AnswerBody encodes an SPacketBodyAnswer (77 bytes): the CONNECT body plus a
// second 32-byte receiverNonce at +45. ProcessAnswer rejects the frame unless
// receiverNonce matches the nonce the host sent in its own CONNECT, so a fuzzed
// receiver nonce drives the "wrong receiver nonce" reject branch.
func AnswerBody(protocol int32, t int64, comp byte, senderNonce, receiverNonce []byte) []byte {
	b := make([]byte, AnswerBodySize)
	binary.LittleEndian.PutUint32(b[0:4], uint32(protocol))
	binary.LittleEndian.PutUint64(b[4:12], uint64(t))
	b[12] = comp
	copyFixed(b[13:45], senderNonce)
	copyFixed(b[45:77], receiverNonce)
	return b
}

// copyFixed copies src into dst, zero-padding or truncating to len(dst).
func copyFixed(dst, src []byte) {
	n := copy(dst, src)
	for i := n; i < len(dst); i++ {
		dst[i] = 0
	}
}
