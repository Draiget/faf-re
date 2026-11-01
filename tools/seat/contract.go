package seat

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"faf-main/tools/fafclient"
	"faf-main/tools/gpgnet"
	"faf-main/tools/journal"
	"faf-main/tools/procs"
)

// Contract puts the game behind an adapter that speaks the FAF client's ICE
// adapter contract (docs/LAUNCHER_ADAPTER_CONTRACT.md): FAF's
// faf-ice-adapter.jar, faf-netbridge, or the launch shim. The seat plays the
// FAF client's part: it starts the adapter with the client's command line,
// talks JSON-RPC to it, and turns the director's GPGNet commands into
// hostGame / joinGame / connectToPeer / disconnectFromPeer calls. IceMsg
// signalling goes between the seats of one run in this process.
type Contract struct {
	fafclient.Adapter
	GameID     uint64           `json:"gameId"`
	IceServers []map[string]any `json:"iceServers"`
	// Bus is the run's IceMsg relay; set by the launcher (local seats only).
	Bus *ContractBus `json:"-"`
}

// ContractBus relays IceMsg between the seats of one run as the lobby server
// does: an adapter's onIceMsg or a native game's IceMsg goes to the receiver's
// adapter (iceMsg) or native game (IceMsg).
type ContractBus struct {
	mu    sync.Mutex
	seats map[int]iceTarget
}

// iceTarget is one seat's way in for relayed IceMsg.
type iceTarget interface {
	iceMsg(from int, msg any) bool
}

func NewContractBus() *ContractBus { return &ContractBus{seats: map[int]iceTarget{}} }

func (b *ContractBus) add(uid int, t iceTarget) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seats[uid] = t
}

func (b *ContractBus) deliver(from, to int, msg any) bool {
	b.mu.Lock()
	t := b.seats[to]
	b.mu.Unlock()
	if t == nil {
		return false
	}
	return t.iceMsg(from, msg)
}

func (c *contractLink) iceMsg(from int, msg any) bool {
	_, err := c.rpc.Call("iceMsg", from, msg)
	return err == nil
}

// contractLink is one seat's client side: the RPC connection to its adapter
// and a GPGNet connection to the seat's own endpoint, on which it stands in
// for the game toward the director.
type contractLink struct {
	s       *Seat
	rpc     *fafclient.Peer
	rpcConn net.Conn
	gpg     net.Conn
	gpgMu   sync.Mutex
}

func (s *Seat) startContract(ctx context.Context) error {
	c, uid := s.cfg.Contract, s.cfg.UID
	if c.Bus == nil {
		return errors.New("contract mode needs the run's IceMsg bus (local seats only)")
	}
	rpcPort, err := freeTCPPort()
	if err != nil {
		return err
	}
	if s.adapterPort, err = freeTCPPort(); err != nil {
		return err
	}
	logDir := filepath.Join(s.cfg.RunDir, fmt.Sprintf("adapter-%d", uid))
	_ = os.MkdirAll(logDir, 0o755)
	a := c.Adapter
	if abs, err := filepath.Abs(a.NativeDir); err == nil {
		a.NativeDir = abs
	}
	argv := a.Command(fafclient.Player{ID: uid, Login: s.cfg.Name}, int(c.GameID), rpcPort, s.adapterPort,
		"mpemu-token", "http://127.0.0.1:1/ice")
	dir := a.NativeDir
	if dir == "" {
		dir = logDir
	}
	proc, err := procs.Start(procs.Spec{
		Name: fmt.Sprintf("adapter-%d", uid), Exe: argv[0], Dir: dir, Args: argv[1:],
		Output: filepath.Join(logDir, "stdout.log"), Env: []string{"LOG_DIR=" + logDir},
	}, s.job)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.adapter = proc
	s.mu.Unlock()
	s.emit(journal.Record{Kind: journal.ProcStart, UID: uid, Text: "adapter",
		Data: map[string]any{"pid": proc.Pid(), "cmd": procs.CommandLine(argv[0], argv[1:])}})
	go s.watchExit(proc, "adapter")

	// IceAdapterImpl.initializeIceAdapterConnection: 50 attempts, 250 ms apart.
	var conn net.Conn
	for attempt := 0; attempt < 50; attempt++ {
		conn, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(rpcPort), time.Second)
		if err == nil {
			break
		}
		select {
		case <-proc.Done():
			return fmt.Errorf("player %d: adapter exited (code %d) before RPC connected; see %s", uid, proc.ExitCode(), logDir)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if err != nil {
		return fmt.Errorf("player %d: RPC connect: %w", uid, err)
	}
	link := &contractLink{s: s, rpcConn: conn}
	link.rpc = fafclient.NewPeer(conn, func(dir string, f fafclient.Frame) {
		kind := fafclient.RPCOut
		if dir == "in" {
			kind = fafclient.RPCIn
		}
		s.emit(journal.Record{Kind: kind, UID: uid, Text: strings.TrimSpace(f.Text)})
	})
	go func() { _ = link.rpc.Serve(conn, link.onCallback) }()

	// The seat's endpoint sees this link as the game; the director's commands
	// arrive on it.
	if link.gpg, err = net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(s.endpoint.Port())); err != nil {
		return err
	}
	go link.readDirector()
	c.Bus.add(uid, link)
	s.mu.Lock()
	s.contract = link
	s.mu.Unlock()

	mode := "normal"
	if s.cfg.AutoLobby {
		mode = "auto"
	}
	if _, err := link.rpc.Call("setLobbyInitMode", mode); err != nil {
		return err
	}
	if c.IceServers != nil {
		if _, err := link.rpc.Call("setIceServers", c.IceServers); err != nil {
			return err
		}
	}
	return nil
}

// readDirector turns the director's GPGNet commands into adapter calls.
func (c *contractLink) readDirector() {
	r := bufio.NewReader(c.gpg)
	uid := c.s.cfg.UID
	for {
		m, err := gpgnet.ReadMessage(r)
		if err != nil {
			return
		}
		switch m.Command {
		case "CreateLobby":
			// The adapter sends its own CreateLobby on Idle, with its lobby port.
		case "HostGame":
			_, _ = c.rpc.Call("hostGame", m.Str(0))
		case "JoinGame":
			remote, _ := m.Int(2)
			_, _ = c.rpc.Call("joinGame", m.Str(1), int(remote))
		case "ConnectToPeer":
			remote, _ := m.Int(2)
			// GPGNet carries no offer flag. One side of each pair must offer;
			// the lower id does, so the host (normally the lowest id) offers
			// to every joiner, as the lobby server has it.
			_, _ = c.rpc.Call("connectToPeer", m.Str(1), int(remote), uid < int(remote))
		case "DisconnectFromPeer":
			remote, _ := m.Int(0)
			_, _ = c.rpc.Call("disconnectFromPeer", int(remote))
		default:
			_, _ = c.rpc.Call("sendToGpgNet", m.Command, m.Args)
		}
	}
}

// onCallback handles the adapter's notifications (IceAdapterCallbacks).
func (c *contractLink) onCallback(m fafclient.Message) {
	uid := c.s.cfg.UID
	switch m.Method {
	case "onGpgNetMessageReceived":
		if len(m.Params) < 2 {
			return
		}
		var cmd string
		_ = json.Unmarshal(m.Params[0], &cmd)
		var raw []json.RawMessage
		_ = json.Unmarshal(m.Params[1], &raw)
		args := make([]any, 0, len(raw))
		for _, a := range raw {
			var v any
			d := json.NewDecoder(strings.NewReader(string(a)))
			d.UseNumber()
			if d.Decode(&v) != nil {
				continue
			}
			switch x := v.(type) {
			case json.Number:
				n, _ := x.Int64()
				args = append(args, int32(n))
			case string:
				args = append(args, x)
			default:
				args = append(args, string(a))
			}
		}
		c.gpgMu.Lock()
		err := gpgnet.WriteMessage(c.gpg, gpgnet.New(cmd, args...))
		c.gpgMu.Unlock()
		if err != nil {
			c.s.emit(journal.Record{Kind: journal.Warn, UID: uid, Text: "contract: forward to director: " + err.Error()})
		}
	case "onIceMsg":
		if len(m.Params) < 3 {
			return
		}
		var from, to int
		_ = json.Unmarshal(m.Params[0], &from)
		_ = json.Unmarshal(m.Params[1], &to)
		var msg any
		_ = json.Unmarshal(m.Params[2], &msg)
		if !c.s.cfg.Contract.Bus.deliver(from, to, msg) {
			c.s.emit(journal.Record{Kind: journal.Warn, UID: uid, Text: fmt.Sprintf("contract: IceMsg for player %d not delivered", to)})
		}
	case "onConnectionStateChanged":
		var state string
		if len(m.Params) > 0 {
			_ = json.Unmarshal(m.Params[0], &state)
		}
		if state == "Disconnected" {
			_, _ = c.rpc.Call("quit") // IceAdapterImpl.onIceAdapterStateChanged
		}
	}
}
