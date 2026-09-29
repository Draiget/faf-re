package gpgnet

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Handler receives what the far side (the game, or an ICE adapter standing in
// front of it) does on one endpoint. Callbacks run on the endpoint's reader
// goroutine, one at a time.
type Handler struct {
	Connected    func(remote string)
	Message      func(Message)
	Disconnected func(err error)
}

// Endpoint is the launcher's GPGNet listener for one player: the port passed
// to the game as `/gpgnet 127.0.0.1:<port>`, or to faf-pioneer as
// `--gpgnet-client-port`. A newer connection replaces an older one, as a
// restarted game reconnecting would.
type Endpoint struct {
	ln      net.Listener
	handler Handler

	mu   sync.Mutex
	conn net.Conn
}

// Listen opens an endpoint on addr ("127.0.0.1:0" picks a free port).
func Listen(addr string, h Handler) (*Endpoint, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("gpgnet listen %s: %w", addr, err)
	}
	e := &Endpoint{ln: ln, handler: h}
	go e.acceptLoop()
	return e, nil
}

// Port is the TCP port the endpoint listens on.
func (e *Endpoint) Port() int { return e.ln.Addr().(*net.TCPAddr).Port }

// Connected reports whether a peer is attached right now.
func (e *Endpoint) Connected() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.conn != nil
}

// Send writes one message to the attached peer.
func (e *Endpoint) Send(m Message) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn == nil {
		return fmt.Errorf("gpgnet: %s: no peer connected", m.Command)
	}
	return WriteMessage(e.conn, m)
}

// Close stops listening and drops the current peer.
func (e *Endpoint) Close() {
	_ = e.ln.Close()
	e.mu.Lock()
	if e.conn != nil {
		_ = e.conn.Close()
	}
	e.mu.Unlock()
}

func (e *Endpoint) acceptLoop() {
	for {
		conn, err := e.ln.Accept()
		if err != nil {
			return
		}
		e.mu.Lock()
		if e.conn != nil {
			_ = e.conn.Close()
		}
		e.conn = conn
		e.mu.Unlock()
		if e.handler.Connected != nil {
			e.handler.Connected(conn.RemoteAddr().String())
		}
		go e.readLoop(conn)
	}
}

func (e *Endpoint) readLoop(conn net.Conn) {
	r := bufio.NewReaderSize(conn, 64<<10)
	var err error
	for {
		var msg Message
		msg, err = ReadMessage(r)
		if err != nil {
			break
		}
		if e.handler.Message != nil {
			e.handler.Message(msg)
		}
	}
	e.mu.Lock()
	current := e.conn == conn
	if current {
		e.conn = nil
	}
	e.mu.Unlock()
	_ = conn.Close()
	if !current {
		return // replaced by a newer connection; not a disconnect of the player
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		err = nil
	}
	if e.handler.Disconnected != nil {
		e.handler.Disconnected(err)
	}
}
