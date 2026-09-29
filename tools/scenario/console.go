package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"faf-main/tools/gpgnet"
	"faf-main/tools/relay"
)

const consoleHelp = `commands:
  state                         players, GameStates, ports, pids (and relay link counters)
  tail [n]                      last n journal records (default 20)
  host <uid>                    send HostGame
  join <uid>|others             JoinGame + ConnectToPeer mesh
  start <uid>|all               start endpoint/adapter/game
  kill <uid>                    terminate a game (and its adapter)
  send <uid> <cmd> [args...]    raw GPGNet message; numeric args are sent as ints
  link <a> <b> [latency=150ms] [jitter=20ms] [loss=0.05] [dup=0.01] [oneway]
  clear <a> <b>                 remove a link's impairment
  isolate <uid> / restore <uid> cut / restore every link of a player (relay mode)
  continue                      leave the console and run the remaining steps
  quit                          stop the run (everything is torn down)
`

// console runs the interactive prompt until "continue", "quit" or ctx ends.
func (r *runner) console(ctx context.Context) error {
	fmt.Fprint(r.out, "\n== interactive console; type 'help'\n")
	lines := make(chan string)
	go func() {
		defer close(lines)
		for r.in.Scan() {
			lines <- r.in.Text()
		}
	}()
	for {
		fmt.Fprint(r.out, "mpemu> ")
		var line string
		select {
		case <-ctx.Done():
			return ctx.Err()
		case l, ok := <-lines:
			if !ok {
				return errQuit // stdin closed
			}
			line = strings.TrimSpace(l)
		}
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		switch f[0] {
		case "continue", "c":
			return nil
		case "quit", "q", "exit":
			return errQuit
		default:
			if err := r.command(ctx, f); err != nil {
				fmt.Fprintf(r.out, "error: %v\n", err)
			}
		}
	}
}

func atoi(s string) (int, error) {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	return v, nil
}

func (r *runner) command(ctx context.Context, f []string) error {
	need := func(n int) error {
		if len(f) < n+1 {
			return fmt.Errorf("%s needs %d argument(s); see help", f[0], n)
		}
		return nil
	}
	switch f[0] {
	case "help", "h", "?":
		fmt.Fprint(r.out, consoleHelp)
	case "state", "s":
		raw, _ := json.MarshalIndent(r.l.Snapshot(), "", "  ")
		fmt.Fprintln(r.out, string(raw))
	case "tail":
		n := 20
		if len(f) > 1 {
			n, _ = strconv.Atoi(f[1])
		}
		for _, rec := range r.j.Tail(n) {
			r.echoAlways(rec)
		}
	case "host":
		if err := need(1); err != nil {
			return err
		}
		uid, err := atoi(f[1])
		if err != nil {
			return err
		}
		c, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		return r.l.HostGame(c, uid)
	case "join":
		if err := need(1); err != nil {
			return err
		}
		c, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		targets := []int{}
		if f[1] == "others" || f[1] == "all" {
			targets = UIDs{Others: true}.Resolve(r.l.Players(), r.l.Host())
		} else {
			uid, err := atoi(f[1])
			if err != nil {
				return err
			}
			targets = append(targets, uid)
		}
		for _, uid := range targets {
			if err := r.l.JoinGame(c, uid); err != nil {
				return err
			}
		}
	case "start":
		if err := need(1); err != nil {
			return err
		}
		targets := r.l.Players()
		if f[1] != "all" {
			uid, err := atoi(f[1])
			if err != nil {
				return err
			}
			targets = []int{uid}
		}
		for _, uid := range targets {
			if err := r.l.Start(ctx, uid); err != nil {
				return err
			}
		}
	case "kill":
		if err := need(1); err != nil {
			return err
		}
		uid, err := atoi(f[1])
		if err != nil {
			return err
		}
		return r.l.Kill(uid)
	case "send":
		if err := need(2); err != nil {
			return err
		}
		uid, err := atoi(f[1])
		if err != nil {
			return err
		}
		var args []any
		for _, a := range f[3:] {
			if v, err := strconv.Atoi(a); err == nil {
				args = append(args, int32(v))
			} else {
				args = append(args, a)
			}
		}
		return r.l.Send(uid, gpgnet.New(f[2], args...))
	case "link", "clear":
		if err := need(2); err != nil {
			return err
		}
		a, err := atoi(f[1])
		if err != nil {
			return err
		}
		b, err := atoi(f[2])
		if err != nil {
			return err
		}
		var imp relay.Impairment
		oneWay := false
		if f[0] == "link" {
			for _, kv := range f[3:] {
				if kv == "oneway" {
					oneWay = true
					continue
				}
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("expected key=value, got %q", kv)
				}
				switch k {
				case "latency":
					imp.Latency, err = time.ParseDuration(v)
				case "jitter":
					imp.Jitter, err = time.ParseDuration(v)
				case "loss":
					imp.Loss, err = strconv.ParseFloat(v, 64)
				case "dup":
					imp.Duplicate, err = strconv.ParseFloat(v, 64)
				default:
					return fmt.Errorf("unknown link setting %q", k)
				}
				if err != nil {
					return fmt.Errorf("%s: %w", k, err)
				}
			}
		}
		return r.l.SetLink(a, b, imp, !oneWay)
	case "isolate", "restore":
		if err := need(1); err != nil {
			return err
		}
		uid, err := atoi(f[1])
		if err != nil {
			return err
		}
		return r.l.Isolate(uid, f[0] == "isolate")
	default:
		return fmt.Errorf("unknown command %q; see help", f[0])
	}
	return nil
}
