package launcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"faf-main/tools/gpgnet"
	"faf-main/tools/hub"
	"faf-main/tools/journal"
	"faf-main/tools/relay"
	"faf-main/tools/seat"
)

// hubSession is the director's connection to a hub.
type hubSession struct {
	client *hub.Client
	run    string
	box    string
	host   string // hub host name as players' machines must reach it
	// apiRoot is the icebreaker API as this machine's ICE adapters reach it
	// (the client's loopback gateway). Agents substitute their own.
	apiRoot string
	stop    context.CancelFunc

	mu    sync.Mutex
	links map[[2]int][2]int // relay pair -> (port for lower uid, port for higher uid)
}

func (l *Launcher) openHub() error {
	c := l.cfg
	u, err := url.Parse(c.Hub)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("hub %q is not a URL", c.Hub)
	}
	client := hub.NewClient(c.Hub, c.HubSecret)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err = client.Info(ctx); err != nil {
		return fmt.Errorf("hub unreachable or secret refused: %w", err)
	}
	h := &hubSession{client: client, run: c.RunID, box: hub.RunBox(c.RunID), host: u.Hostname(),
		links: map[[2]int][2]int{}}
	listenCtx, stop := context.WithCancel(context.Background())
	h.stop = stop
	ready := make(chan struct{})
	var once sync.Once
	go client.Listen(listenCtx, h.box, l.onHub, func() { once.Do(func() { close(ready) }) })
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		stop()
		return errors.New("hub: could not open the director's event stream")
	}
	l.hub = h
	if c.Mode == ModeICE {
		if err = client.Watch(ctx, c.GameID, h.box); err != nil {
			stop()
			return err
		}
		if h.apiRoot, err = client.Gateway(); err != nil {
			stop()
			return err
		}
	}
	l.j.Note(journal.Note, 0, fmt.Sprintf("hub %s, run %s, mode %s", c.Hub, c.RunID, c.Mode), nil)
	return nil
}

// onHub receives what agents and the hub's services report.
func (l *Launcher) onHub(env hub.Envelope) {
	switch env.Type {
	case hub.TypeRecord:
		if env.Record != nil {
			l.record(env.Record.Record())
		}
	case hub.TypeStarted, hub.TypeError:
		if p := l.players[env.UID]; p != nil {
			if rs, ok := p.seat.(*remoteSeat); ok {
				select {
				case rs.replies <- env:
				default:
				}
			}
		}
	}
}

// remoteSeat is a player whose game runs on another machine, via its agent.
type remoteSeat struct {
	l       *Launcher
	uid     int
	agent   string
	cfg     seat.Config
	replies chan hub.Envelope

	mu        sync.Mutex
	lobbyPort int
}

func (r *remoteSeat) send(env hub.Envelope) error {
	env.Run, env.Reply, env.UID, env.Agent = r.l.hub.run, r.l.hub.box, r.uid, r.agent
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return r.l.hub.client.Send(ctx, hub.AgentBox(r.agent), env)
}

func (r *remoteSeat) Start(ctx context.Context) error {
	cfg := r.cfg
	if err := r.send(hub.Envelope{Type: hub.TypeStart, Seat: &cfg}); err != nil {
		return err
	}
	select {
	case env := <-r.replies:
		if env.Type == hub.TypeError {
			return fmt.Errorf("player %d on agent %q: %s", r.uid, r.agent, env.Error)
		}
		r.mu.Lock()
		r.lobbyPort = env.Port
		r.mu.Unlock()
		if p := r.l.players[r.uid]; p != nil && env.Host != "" {
			p.mu.Lock()
			p.host = env.Host
			p.mu.Unlock()
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("player %d: agent %q did not answer (is it running and connected to the hub?): %w",
			r.uid, r.agent, ctx.Err())
	}
}

func (r *remoteSeat) Send(m gpgnet.Message) error {
	return r.send(hub.Envelope{Type: hub.TypeSend, Cmd: m.Command, Args: gpgnet.EncodeArgs(m.Args)})
}

func (r *remoteSeat) Kill()  { _ = r.send(hub.Envelope{Type: hub.TypeKill}) }
func (r *remoteSeat) Close() { _ = r.send(hub.Envelope{Type: hub.TypeClose}) }

func (r *remoteSeat) LobbyPort() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lobbyPort
}

func (r *remoteSeat) Snapshot() seat.Snapshot {
	return seat.Snapshot{LobbyPort: r.LobbyPort()}
}

// hubRelayAddr is where viewer's game sends to reach target through the hub.
func (l *Launcher) hubRelayAddr(viewer, target int) (string, error) {
	h := l.hub
	a, b := viewer, target
	if a > b {
		a, b = b, a
	}
	h.mu.Lock()
	ports, ok := h.links[[2]int{a, b}]
	h.mu.Unlock()
	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		pa, pb, err := h.client.RelayLink(ctx, h.run, h.box, a, b)
		if err != nil {
			return "", err
		}
		ports = [2]int{pa, pb}
		h.mu.Lock()
		h.links[[2]int{a, b}] = ports
		h.mu.Unlock()
	}
	port := ports[0]
	if viewer == b {
		port = ports[1]
	}
	return net.JoinHostPort(h.host, strconv.Itoa(port)), nil
}

// SetLink changes the impairment of the link from -> to (both ways when both
// is set), on the local relay or the hub's.
func (l *Launcher) SetLink(from, to int, imp relay.Impairment, both bool) error {
	switch {
	case l.relay != nil:
		return l.relay.Set(from, to, imp, both)
	case l.hub != nil && l.cfg.Mode == ModeRelay:
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return l.hub.client.RelayImpair(ctx, l.hub.run, from, to, imp, both)
	}
	return errors.New("link impairment needs mode relay")
}

// Isolate cuts (or restores) all of a player's links. ModeRelay only.
func (l *Launcher) Isolate(uid int, blocked bool) error {
	switch {
	case l.relay != nil:
		l.relay.Isolate(uid, blocked)
		return nil
	case l.hub != nil && l.cfg.Mode == ModeRelay:
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return l.hub.client.RelayIsolate(ctx, l.hub.run, uid, blocked)
	}
	return errors.New("isolate needs mode relay")
}

// LinkStats reports relay counters, local or on the hub.
func (l *Launcher) LinkStats() map[string]relay.DirStats {
	switch {
	case l.relay != nil:
		return l.relay.Stats()
	case l.hub != nil && l.cfg.Mode == ModeRelay:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s, err := l.hub.client.RelayStats(ctx, l.hub.run); err == nil {
			return s
		}
	}
	return nil
}

func (l *Launcher) closeHub() {
	if l.hub == nil {
		return
	}
	if l.cfg.Mode == ModeRelay {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if s, err := l.hub.client.RelayStats(ctx, l.hub.run); err == nil {
			l.j.Add(journal.Record{Kind: journal.RelayStats, Text: "final (hub)", Data: s})
		}
		_ = l.hub.client.RelayClose(ctx, l.hub.run)
		cancel()
	}
	time.Sleep(300 * time.Millisecond) // let agents' last records arrive
	l.hub.stop()
	l.hub.client.Close()
}
