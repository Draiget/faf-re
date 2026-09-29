// Package gpgnet implements the launcher side of the GPGNet control protocol
// that Forged Alliance speaks over TCP (`/gpgnet host:port`).
//
// Wire format, little endian throughout:
//
//	message := string(command) int32(argCount) arg*
//	string  := int32(length) bytes
//	arg     := 0x00 int32          -- SNetCommandArg::NETARG_Num
//	         | 0x01 string         -- SNetCommandArg::NETARG_String
//	         | 0x02 string         -- SNetCommandArg::NETARG_Data (binary, e.g. NAT packets)
//
// The engine side is moho::CGpgNetInterface (src/sdk/moho/net/CGpgNetInterface.cpp).
package gpgnet

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const (
	kindInt    byte = 0x00
	kindString byte = 0x01
	kindData   byte = 0x02

	// Sanity limits only. Unlike faf-pioneer's reader (10 args, 64 KiB strings)
	// these are far above anything the game sends: end-of-game JsonStats alone
	// passes 64 KiB in larger games.
	maxArgs        = 1 << 12
	maxStringBytes = 64 << 20
)

// Data is a binary argument (NETARG_Data), as opposed to a text string.
type Data []byte

// Message is one GPGNet command with its arguments. Arguments are int32,
// string or Data.
type Message struct {
	Command string `json:"cmd"`
	Args    []any  `json:"args,omitempty"`
}

// New builds a message, normalising Go integer types to int32.
func New(command string, args ...any) Message {
	norm := make([]any, 0, len(args))
	for _, a := range args {
		switch v := a.(type) {
		case int:
			norm = append(norm, int32(v))
		case int64:
			norm = append(norm, int32(v))
		case uint:
			norm = append(norm, int32(v))
		case uint16:
			norm = append(norm, int32(v))
		case uint32:
			norm = append(norm, int32(v))
		case bool:
			if v {
				norm = append(norm, int32(1))
			} else {
				norm = append(norm, int32(0))
			}
		default:
			norm = append(norm, a)
		}
	}
	return Message{Command: command, Args: norm}
}

// Str returns argument i as text, or "" when it is missing or numeric.
func (m Message) Str(i int) string {
	if i >= len(m.Args) {
		return ""
	}
	switch v := m.Args[i].(type) {
	case string:
		return v
	case Data:
		return string(v)
	}
	return ""
}

// Int returns argument i as an integer.
func (m Message) Int(i int) (int32, bool) {
	if i >= len(m.Args) {
		return 0, false
	}
	v, ok := m.Args[i].(int32)
	return v, ok
}

func (m Message) String() string {
	var b strings.Builder
	b.WriteString(m.Command)
	for _, a := range m.Args {
		b.WriteByte(' ')
		switch v := a.(type) {
		case string:
			if len(v) > 120 {
				fmt.Fprintf(&b, "%q...(%d bytes)", v[:120], len(v))
			} else {
				fmt.Fprintf(&b, "%q", v)
			}
		case Data:
			fmt.Fprintf(&b, "<data %d bytes>", len(v))
		default:
			fmt.Fprintf(&b, "%v", v)
		}
	}
	return b.String()
}

func readString(r io.Reader) ([]byte, error) {
	var n int32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	if n < 0 || n > maxStringBytes {
		return nil, fmt.Errorf("gpgnet: string length %d out of range", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadMessage reads one message. io.EOF is returned unwrapped on a clean close.
func ReadMessage(r *bufio.Reader) (Message, error) {
	cmd, err := readString(r)
	if err != nil {
		return Message{}, err
	}
	var count int32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return Message{}, fmt.Errorf("gpgnet: %s: arg count: %w", cmd, err)
	}
	if count < 0 || count > maxArgs {
		return Message{}, fmt.Errorf("gpgnet: %s: arg count %d out of range", cmd, count)
	}
	msg := Message{Command: string(cmd), Args: make([]any, 0, count)}
	for i := int32(0); i < count; i++ {
		kind, err := r.ReadByte()
		if err != nil {
			return Message{}, fmt.Errorf("gpgnet: %s: arg %d kind: %w", cmd, i, err)
		}
		switch kind {
		case kindInt:
			var v int32
			if err := binary.Read(r, binary.LittleEndian, &v); err != nil {
				return Message{}, fmt.Errorf("gpgnet: %s: arg %d: %w", cmd, i, err)
			}
			msg.Args = append(msg.Args, v)
		case kindString:
			s, err := readString(r)
			if err != nil {
				return Message{}, fmt.Errorf("gpgnet: %s: arg %d: %w", cmd, i, err)
			}
			// Kept verbatim. The FAF lobby server rewrites "/t" and "/n" to tab
			// and newline here, which also mangles strings such as "/numgames";
			// a test journal should hold what the game actually sent.
			msg.Args = append(msg.Args, string(s))
		case kindData:
			s, err := readString(r)
			if err != nil {
				return Message{}, fmt.Errorf("gpgnet: %s: arg %d: %w", cmd, i, err)
			}
			msg.Args = append(msg.Args, Data(s))
		default:
			return Message{}, fmt.Errorf("gpgnet: %s: arg %d has unknown kind 0x%02x", cmd, i, kind)
		}
	}
	return msg, nil
}

// Encode serialises one message.
func Encode(m Message) ([]byte, error) {
	var b bytes.Buffer
	putString := func(s []byte) {
		_ = binary.Write(&b, binary.LittleEndian, int32(len(s)))
		b.Write(s)
	}
	putString([]byte(m.Command))
	_ = binary.Write(&b, binary.LittleEndian, int32(len(m.Args)))
	for i, a := range New(m.Command, m.Args...).Args {
		switch v := a.(type) {
		case int32:
			b.WriteByte(kindInt)
			_ = binary.Write(&b, binary.LittleEndian, v)
		case string:
			b.WriteByte(kindString)
			putString([]byte(v))
		case Data:
			b.WriteByte(kindData)
			putString(v)
		case []byte:
			b.WriteByte(kindData)
			putString(v)
		default:
			return nil, fmt.Errorf("gpgnet: %s: arg %d has unsupported type %T", m.Command, i, a)
		}
	}
	return b.Bytes(), nil
}

// WriteMessage writes one message in a single Write call.
func WriteMessage(w io.Writer, m Message) error {
	buf, err := Encode(m)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}
