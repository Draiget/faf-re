package fafclient

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// Framing of the JJsonRpc library both sides use (client fork
// micheljung/JJsonRpc 01a7fba5f4, adapter fork faforever/JJsonRpc 37669e0fed;
// JJsonPeer.run, read back from the shipped faf-ice-adapter.jar with javap):
// every message is written with PrintWriter.println, and the reader takes the
// stream one byte at a time, appends (char)byte, counts '{' as +1 and '}' as -1
// without looking at strings, and hands the text over when the count returns
// to zero. ReadFrame reproduces that reader exactly, so a peer that writes
// something the Java side would split wrongly fails here too.

// Frame is one message as the Java reader would cut it out of the stream.
type Frame struct {
	Text string
	// NonASCII is set when the frame holds a byte >= 0x80. The Java reader
	// casts each byte to a char on its own, so UTF-8 text arrives mangled.
	NonASCII bool
}

// ReadFrame returns the next frame. Bytes before the first '{' (the newline
// println leaves after the previous message) are part of the frame, as in
// Java, and are trimmed by the JSON decoder.
func ReadFrame(r *bufio.Reader) (Frame, error) {
	var buf []byte
	depth := 0
	nonASCII := false
	for {
		b, err := r.ReadByte()
		if err != nil {
			return Frame{}, err
		}
		buf = append(buf, b)
		if b >= 0x80 {
			nonASCII = true
		}
		switch b {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return Frame{Text: string(buf), NonASCII: nonASCII}, nil
			}
		}
	}
}

// Message is a JSON-RPC 2.0 request, notification or response. Params are
// positional, as JSONRPC2Request builds them from the proxy's argument list.
type Message struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      *int64            `json:"id,omitempty"`
	Method  string            `json:"method,omitempty"`
	Params  []json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage   `json:"result,omitempty"`
	Error   *RPCError         `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Peer is one end of a JJsonRpc connection.
type Peer struct {
	w      io.Writer
	wmu    sync.Mutex
	nextID atomic.Int64
	trace  func(dir string, f Frame)

	mu      sync.Mutex
	pending map[int64]chan Message
}

func NewPeer(w io.Writer, trace func(dir string, f Frame)) *Peer {
	return &Peer{w: w, trace: trace, pending: map[int64]chan Message{}}
}

// writeLine writes one message followed by a newline, as println does.
func (p *Peer) writeLine(m Message) error {
	m.JSONRPC = "2.0"
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if p.trace != nil {
		p.trace("out", Frame{Text: string(b)})
	}
	_, err = p.w.Write(append(b, '\n'))
	return err
}

func params(args []any) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(args))
	for _, a := range args {
		b, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// Call sends a request with an id, as the client's proxy does for every
// method (sendAsyncRequest for void methods, sendSyncRequest otherwise), and
// returns a channel that receives the response.
func (p *Peer) Call(method string, args ...any) (<-chan Message, error) {
	ps, err := params(args)
	if err != nil {
		return nil, err
	}
	id := p.nextID.Add(1)
	ch := make(chan Message, 1)
	p.mu.Lock()
	p.pending[id] = ch
	p.mu.Unlock()
	if err := p.writeLine(Message{ID: &id, Method: method, Params: ps}); err != nil {
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return nil, err
	}
	return ch, nil
}

// Notify sends a notification (no id), as the adapter's RPCService does for
// every callback.
func (p *Peer) Notify(method string, args ...any) error {
	ps, err := params(args)
	if err != nil {
		return err
	}
	return p.writeLine(Message{Method: method, Params: ps})
}

// Respond answers a request.
func (p *Peer) Respond(id int64, result any) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return p.writeLine(Message{ID: &id, Result: b})
}

// Serve reads frames until the stream ends. Responses complete their pending
// call; requests and notifications go to handle.
func (p *Peer) Serve(r io.Reader, handle func(Message)) error {
	br := bufio.NewReader(r)
	for {
		f, err := ReadFrame(br)
		if err != nil {
			return err
		}
		if p.trace != nil {
			p.trace("in", f)
		}
		var m Message
		if err := json.Unmarshal([]byte(f.Text), &m); err != nil {
			return fmt.Errorf("jsonrpc: bad frame %q: %w", f.Text, err)
		}
		if m.Method == "" && m.ID != nil {
			p.mu.Lock()
			ch := p.pending[*m.ID]
			delete(p.pending, *m.ID)
			p.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		handle(m)
	}
}
