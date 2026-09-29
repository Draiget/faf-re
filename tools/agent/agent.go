// Package agent runs the seats of one test PC for a director elsewhere. It
// connects to the hub outbound, takes start / send / kill / close commands
// from its mailbox, runs each seat with this machine's own paths (game,
// adapter, preferences) and streams every record the seat produces back to
// the director that asked for it.
package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"faf-main/tools/gpgnet"
	"faf-main/tools/hub"
	"faf-main/tools/journal"
	"faf-main/tools/procs"
	"faf-main/tools/seat"
)

// Options configure an agent.
type Options struct {
	Hub  *hub.Client
	Name string
	// Advertise is how other machines reach games on this one (direct mode):
	// a LAN name or address.
	Advertise string
	// RunsDir receives one directory per run (logs, journal, prefs).
	RunsDir string
	// FAFBin is this machine's FAF bin folder; used when a path the director
	// sent does not exist here.
	FAFBin string
	// Exe, when set, replaces the game executable the director asks for.
	Exe string
	// Adapter is this machine's faf-adapter.exe (ICE seats).
	Adapter string
	// Secret signs the ICE adapters' access tokens (the hub's secret).
	Secret string
	Out    io.Writer
}

type run struct {
	id      string
	reply   string
	journal *journal.Journal
	outbox  chan journal.Record
	seats   map[int]*seat.Seat

	mu     sync.Mutex
	closed bool // outbox is closed; late records (an exit after Close) are dropped
}

func (r *run) emit(rec journal.Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.journal.Add(rec)
	r.outbox <- rec
}

// Agent is a running agent.
type Agent struct {
	opts Options
	job  *procs.Job
	mu   sync.Mutex
	runs map[string]*run
}

// Run serves until ctx ends, then tears every seat down.
func Run(ctx context.Context, opts Options) error {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	job, err := procs.NewJob()
	if err != nil {
		return err
	}
	defer job.Close()
	if _, err = opts.Hub.Info(ctx); err != nil {
		return fmt.Errorf("agent: hub not reachable or secret refused: %w", err)
	}
	a := &Agent{opts: opts, job: job, runs: map[string]*run{}}
	fmt.Fprintf(opts.Out, "agent %q: connected to hub %s, advertising %s\n", opts.Name, opts.Hub.Base, opts.Advertise)
	opts.Hub.Listen(ctx, hub.AgentBox(opts.Name), func(env hub.Envelope) { a.handle(ctx, env) },
		func() { fmt.Fprintf(opts.Out, "agent %q: listening\n", opts.Name) })
	a.closeAll()
	opts.Hub.Close()
	return nil
}

func (a *Agent) runFor(env hub.Envelope) (*run, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.runs[env.Run]
	if r != nil {
		return r, nil
	}
	if env.Reply == "" {
		return nil, fmt.Errorf("unknown run %q", env.Run)
	}
	dir := filepath.Join(a.opts.RunsDir, env.Run)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	j, err := journal.New(filepath.Join(dir, "agent-journal.jsonl"), nil)
	if err != nil {
		return nil, err
	}
	r = &run{id: env.Run, reply: env.Reply, journal: j, outbox: make(chan journal.Record, 4096), seats: map[int]*seat.Seat{}}
	a.runs[env.Run] = r
	go a.forward(r)
	return r, nil
}

// forward posts a run's records to its director in order, riding out short
// hub outages.
func (a *Agent) forward(r *run) {
	for rec := range r.outbox {
		env := hub.Envelope{Type: hub.TypeRecord, Run: r.id, Agent: a.opts.Name, Record: hub.ToWire(rec)}
		for attempt := 0; ; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := a.opts.Hub.Send(ctx, r.reply, env)
			cancel()
			if err == nil {
				break
			}
			if attempt == 5 {
				fmt.Fprintf(a.opts.Out, "agent: dropped a record for run %s: %v\n", r.id, err)
				break
			}
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
	}
}

func (a *Agent) reply(r *run, env hub.Envelope) {
	env.Run, env.Agent = r.id, a.opts.Name
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.opts.Hub.Send(ctx, r.reply, env); err != nil {
		fmt.Fprintf(a.opts.Out, "agent: reply %s for player %d failed: %v\n", env.Type, env.UID, err)
	}
}

// localize makes a seat configuration fit this machine.
func (a *Agent) localize(cfg seat.Config, runDir string) (seat.Config, error) {
	cfg.RunDir = runDir
	if a.opts.Exe != "" {
		cfg.Exe = a.opts.Exe
	} else if _, err := os.Stat(cfg.Exe); err != nil && a.opts.FAFBin != "" {
		cfg.Exe = filepath.Join(a.opts.FAFBin, filepath.Base(cfg.Exe))
	}
	if _, err := os.Stat(cfg.Init); err != nil && a.opts.FAFBin != "" {
		cfg.Init = filepath.Join(a.opts.FAFBin, filepath.Base(cfg.Init))
	}
	if cfg.Dir != "" {
		if _, err := os.Stat(cfg.Dir); err != nil {
			cfg.Dir = ""
		}
	}
	if cfg.Prefs != seat.PrefsShared {
		cfg.Prefs = filepath.Join(seat.PrefsDir(), "Game.prefs") // this user's own preferences
	}
	if cfg.ICE != nil {
		// The director's API root is a loopback gateway on its own machine.
		root, err := a.opts.Hub.Gateway()
		if err != nil {
			return cfg, err
		}
		ice := *cfg.ICE
		ice.Adapter, ice.Secret, ice.APIRoot = a.opts.Adapter, a.opts.Secret, root
		cfg.ICE = &ice
	}
	return cfg, nil
}

func (a *Agent) handle(ctx context.Context, env hub.Envelope) {
	r, err := a.runFor(env)
	if err != nil {
		fmt.Fprintf(a.opts.Out, "agent: %s for player %d: %v\n", env.Type, env.UID, err)
		return
	}
	a.mu.Lock()
	s := r.seats[env.UID]
	a.mu.Unlock()

	switch env.Type {
	case hub.TypeStart:
		if env.Seat == nil {
			a.reply(r, hub.Envelope{Type: hub.TypeError, UID: env.UID, Error: "start without a seat"})
			return
		}
		if s == nil {
			cfg, err := a.localize(*env.Seat, filepath.Join(a.opts.RunsDir, r.id))
			if err == nil {
				s, err = seat.New(cfg, a.job, r.emit)
			}
			if err != nil {
				a.reply(r, hub.Envelope{Type: hub.TypeError, UID: env.UID, Error: err.Error()})
				return
			}
			a.mu.Lock()
			r.seats[env.UID] = s
			a.mu.Unlock()
		}
		fmt.Fprintf(a.opts.Out, "agent: starting player %d for run %s\n", env.UID, r.id)
		go func(s *seat.Seat) {
			if err := s.Start(ctx); err != nil {
				a.reply(r, hub.Envelope{Type: hub.TypeError, UID: env.UID, Error: err.Error()})
				return
			}
			a.reply(r, hub.Envelope{Type: hub.TypeStarted, UID: env.UID, Host: a.opts.Advertise, Port: s.LobbyPort()})
		}(s)
	case hub.TypeSend:
		if s != nil {
			_ = s.Send(gpgnet.Message{Command: env.Cmd, Args: gpgnet.DecodeArgs(env.Args)})
		}
	case hub.TypeKill:
		if s != nil {
			s.Kill()
		}
	case hub.TypeClose:
		if s != nil {
			s.Close()
			a.mu.Lock()
			delete(r.seats, env.UID)
			empty := len(r.seats) == 0
			if empty {
				delete(a.runs, r.id)
			}
			a.mu.Unlock()
			if empty {
				a.finish(r)
			}
		}
	}
}

func (a *Agent) finish(r *run) {
	time.Sleep(200 * time.Millisecond) // let the seat's last records reach the outbox
	r.mu.Lock()
	r.closed = true
	close(r.outbox)
	r.mu.Unlock()
	r.journal.Close()
	fmt.Fprintf(a.opts.Out, "agent: run %s finished\n", r.id)
}

func (a *Agent) closeAll() {
	a.mu.Lock()
	runs := a.runs
	a.runs = map[string]*run{}
	a.mu.Unlock()
	for _, r := range runs {
		for _, s := range r.seats {
			s.Close()
		}
		a.finish(r)
	}
}
