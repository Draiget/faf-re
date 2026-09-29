package scenario

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"faf-main/tools/gpgnet"
	"faf-main/tools/journal"
	"faf-main/tools/launcher"
)

// Options configure one run.
type Options struct {
	// RunDir receives the journal, game/adapter logs and result.json.
	RunDir string
	// Verbose echoes every journal record, not just the interesting ones.
	Verbose bool
	// Console is where interactive steps read commands (os.Stdin by default).
	Console io.Reader
	// Out receives progress output (os.Stdout by default).
	Out io.Writer
	// HTTPAddr / TurnPort / TurnIP override the service addresses (ICE mode).
	HTTPAddr string
	TurnPort int
	TurnIP   string
	// Hub overrides the scenario's hub URL; HubSecret authenticates to it.
	Hub, HubSecret string
	// Advertise is how other machines reach games on this one.
	Advertise string
}

// Result is what a run concluded.
type Result struct {
	Scenario string        `json:"scenario"`
	Pass     bool          `json:"pass"`
	Failures []string      `json:"failures,omitempty"`
	Duration time.Duration `json:"duration"`
	RunDir   string        `json:"runDir"`
	Final    any           `json:"final,omitempty"`
}

type runner struct {
	sc   *Scenario
	opts Options
	l    *launcher.Launcher
	j    *journal.Journal
	out  io.Writer
	in   *bufio.Scanner
}

// Run executes a scenario and tears everything down afterwards.
func Run(ctx context.Context, sc *Scenario, opts Options) (Result, error) {
	start := time.Now()
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.Console == nil {
		opts.Console = os.Stdin
	}
	if opts.RunDir == "" {
		opts.RunDir = filepath.Join("runs", time.Now().Format("20060102-150405")+"-"+sanitize(sc.Name))
	}
	abs, err := filepath.Abs(opts.RunDir)
	if err == nil {
		opts.RunDir = abs
	}
	if err = os.MkdirAll(opts.RunDir, 0o755); err != nil {
		return Result{}, err
	}

	r := &runner{sc: sc, opts: opts, out: opts.Out, in: bufio.NewScanner(opts.Console)}
	r.j, err = journal.New(filepath.Join(opts.RunDir, "journal.jsonl"), r.echo)
	if err != nil {
		return Result{}, err
	}
	defer r.j.Close()

	cfg := sc.Config
	cfg.RunDir = opts.RunDir
	cfg.HTTPAddr, cfg.TurnPort, cfg.TurnIP = opts.HTTPAddr, opts.TurnPort, opts.TurnIP
	if opts.Hub != "" {
		cfg.Hub = opts.Hub
	}
	cfg.HubSecret, cfg.Advertise = opts.HubSecret, opts.Advertise
	cfg.RunID = filepath.Base(opts.RunDir)
	r.l, err = launcher.New(cfg, r.j)
	if err != nil {
		return Result{}, err
	}

	timeout := sc.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c := r.l.Config()
	fmt.Fprintf(r.out, "== %s: %d players, mode=%s lobby=%s map=%s\n== run dir: %s\n",
		sc.Name, len(c.Players), c.Mode, c.Lobby, c.Map, opts.RunDir)

	// Steps run under a context that also ends when the last game instance has
	// exited, so a session whose clients are all closed does not sit in a
	// wait or at the console prompt until its timeout.
	stepCtx, stopSteps := context.WithCancelCause(ctx)
	defer stopSteps(nil)
	go func() {
		select {
		case <-r.l.GamesGone():
			stopSteps(errGamesGone)
		case <-stepCtx.Done():
		}
	}()

	var failures []string
	// gamesGone ends the run from step i on. It is only a failure when a step
	// still to come needed a running game; otherwise the session is over.
	gamesGone := func(i int) {
		for k := i; k < len(sc.Steps); k++ {
			if sc.Steps[k].needsGames() {
				failures = append(failures, fmt.Sprintf("step #%d (%s): every game instance exited before it ran", k+1, sc.Steps[k]))
				return
			}
		}
		r.j.Note(journal.Note, 0, "every game instance has exited; ending the run", nil)
	}
	for i, step := range sc.Steps {
		if errors.Is(context.Cause(stepCtx), errGamesGone) {
			gamesGone(i)
			break
		}
		r.j.Add(journal.Record{Kind: journal.Step, Text: fmt.Sprintf("#%d %s", i+1, step)})
		err = r.step(stepCtx, step)
		if err == nil {
			continue
		}
		switch {
		case errors.Is(err, errQuit):
			r.j.Note(journal.Note, 0, "stopped from the console", nil)
		case errors.Is(context.Cause(stepCtx), errGamesGone) && !step.needsGames():
			gamesGone(i + 1)
		case errors.Is(context.Cause(stepCtx), errGamesGone):
			failures = append(failures, fmt.Sprintf("step #%d (%s): every game instance exited before it completed", i+1, step))
		case ctx.Err() != nil && errors.Is(err, context.Canceled):
			failures = append(failures, fmt.Sprintf("step #%d (%s): interrupted", i+1, step))
		default:
			failures = append(failures, fmt.Sprintf("step #%d (%s): %v", i+1, step, err))
		}
		break
	}

	failures = append(failures, r.check(sc.Expect)...)
	final := r.l.Snapshot()
	r.l.Close()

	res := Result{Scenario: sc.Name, Pass: len(failures) == 0, Failures: failures,
		Duration: time.Since(start).Round(time.Millisecond), RunDir: opts.RunDir, Final: final}
	r.j.Add(journal.Record{Kind: journal.Verdict, Text: verdictText(res.Pass), Data: res})
	if raw, err := json.MarshalIndent(res, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(opts.RunDir, "result.json"), raw, 0o644)
	}
	fmt.Fprintf(r.out, "\n== %s: %s in %s\n", sc.Name, verdictText(res.Pass), res.Duration)
	for _, f := range failures {
		fmt.Fprintf(r.out, "   FAIL %s\n", f)
	}
	fmt.Fprintf(r.out, "== journal: %s\n", filepath.Join(opts.RunDir, "journal.jsonl"))
	return res, nil
}

func verdictText(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

var (
	errQuit      = errors.New("quit")
	errGamesGone = errors.New("every game instance has exited")
)

func withTimeout(ctx context.Context, d, def time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = def
	}
	return context.WithTimeout(ctx, d)
}

func (r *runner) step(ctx context.Context, s Step) error {
	all := r.l.Players()
	switch {
	case s.Start != nil:
		for _, uid := range s.Start.Resolve(all, r.l.Host()) {
			if err := r.l.Start(ctx, uid); err != nil {
				return err
			}
		}
	case s.Host != 0:
		c, cancel := withTimeout(ctx, 0, 3*time.Minute)
		defer cancel()
		return r.l.HostGame(c, s.Host)
	case s.Join != nil:
		c, cancel := withTimeout(ctx, 0, 3*time.Minute)
		defer cancel()
		for _, uid := range s.Join.Resolve(all, r.l.Host()) {
			if uid == r.l.Host() {
				continue
			}
			if err := r.l.JoinGame(c, uid); err != nil {
				return err
			}
		}
	case s.WaitState != nil:
		c, cancel := withTimeout(ctx, s.WaitState.Timeout, 3*time.Minute)
		defer cancel()
		sel := s.WaitState.UIDs
		if !sel.All && !sel.Others && len(sel.List) == 0 {
			sel.All = true
		}
		for _, uid := range sel.Resolve(all, r.l.Host()) {
			if err := r.l.WaitState(c, uid, s.WaitState.State); err != nil {
				return err
			}
		}
	case s.WaitMessage != nil:
		c, cancel := withTimeout(ctx, s.WaitMessage.Timeout, 3*time.Minute)
		defer cancel()
		if _, err := r.j.WaitFor(c, 0, s.WaitMessage.matches); err != nil {
			return fmt.Errorf("no matching message: %w", err)
		}
	case s.Wait != 0:
		select {
		case <-time.After(s.Wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	case s.Link != nil:
		return r.l.SetLink(s.Link.From, s.Link.To, s.Link.Impairment, !s.Link.OneWay)
	case s.Isolate != 0:
		return r.l.Isolate(s.Isolate, true)
	case s.Restore != 0:
		return r.l.Isolate(s.Restore, false)
	case s.Kill != nil:
		for _, uid := range s.Kill.Resolve(all, r.l.Host()) {
			if err := r.l.Kill(uid); err != nil {
				return err
			}
		}
	case s.Send != nil:
		return r.l.Send(s.Send.UID, gpgnet.New(s.Send.Cmd, normalizeArgs(s.Send.Args)...))
	case s.Check != nil:
		if f := r.check(*s.Check); len(f) > 0 {
			return errors.New(strings.Join(f, "; "))
		}
	case s.Interactive:
		return r.console(ctx)
	case s.Note != "":
		r.j.Note(journal.Note, 0, s.Note, nil)
	default:
		return errors.New("step has no action")
	}
	return nil
}

func normalizeArgs(in []any) []any {
	out := make([]any, 0, len(in))
	for _, a := range in {
		switch v := a.(type) {
		case int:
			out = append(out, int32(v))
		case float64:
			out = append(out, int32(v))
		case bool:
			out = append(out, v)
		default:
			out = append(out, fmt.Sprint(v))
		}
	}
	return out
}

func (m Match) matches(rec journal.Record) bool {
	kind := m.Kind
	if kind == "" {
		kind = journal.GpgIn
	}
	if rec.Kind != kind || (m.UID != 0 && rec.UID != m.UID) {
		return false
	}
	if m.Cmd != "" && !strings.EqualFold(rec.Command, m.Cmd) && !strings.EqualFold(rec.Text, m.Cmd) {
		return false
	}
	if m.Arg == "" {
		return true
	}
	for _, a := range rec.Args {
		if strings.Contains(fmt.Sprint(a), m.Arg) {
			return true
		}
	}
	return strings.Contains(rec.Text, m.Arg)
}

// check evaluates expectations against the journal.
func (r *runner) check(e Expect) []string {
	var fails []string
	players := r.l.Players()
	if e.AllLaunched {
		for _, uid := range players {
			launched := r.j.Query(func(rec journal.Record) bool {
				return rec.Kind == journal.GpgIn && rec.UID == uid && rec.Command == "GameState" &&
					len(rec.Args) > 0 && rec.Args[0] == "Launching"
			})
			if len(launched) == 0 {
				p, _ := r.l.Player(uid)
				fails = append(fails, fmt.Sprintf("player %d never launched (last GameState %q)", uid, p.State()))
			}
		}
	}
	if e.NoDesync {
		if d := r.j.Query(Match{Cmd: "Desync"}.matches); len(d) > 0 {
			fails = append(fails, fmt.Sprintf("%d Desync report(s), first from player %d: %v", len(d), d[0].UID, d[0].Args))
		}
	}
	if e.NoCrash {
		gameExited := map[int]bool{}
		for _, rec := range r.j.Query(func(rec journal.Record) bool { return rec.Kind == journal.ProcExit }) {
			data, _ := rec.Data.(map[string]any)
			killed, _ := data["killedByMpemu"].(bool)
			if rec.Text == "game" {
				gameExited[rec.UID] = true
			}
			if killed || (rec.Text == "adapter" && gameExited[rec.UID]) {
				continue // an adapter follows its game out; that is not a crash
			}
			how := "crashed or was closed"
			if toInt(data["code"]) == 0 {
				how = "exited cleanly (closed?)"
			}
			fails = append(fails, fmt.Sprintf("player %d %s %s on its own (code %v)", rec.UID, rec.Text, how, data["code"]))
		}
	}
	for _, m := range e.Present {
		if len(r.j.Query(m.matches)) == 0 {
			fails = append(fails, fmt.Sprintf("expected record missing: %+v", m))
		}
	}
	for _, m := range e.Absent {
		if got := r.j.Query(m.matches); len(got) > 0 {
			fails = append(fails, fmt.Sprintf("unexpected record (%d): %+v, first: %s %v", len(got), m, got[0].Command, got[0].Args))
		}
	}
	if e.MinTurnAllocations > 0 {
		n := len(r.j.Query(func(rec journal.Record) bool { return rec.Kind == journal.TurnAlloc }))
		if n < e.MinTurnAllocations {
			fails = append(fails, fmt.Sprintf("TURN allocations %d < %d (relay not used)", n, e.MinTurnAllocations))
		}
	}
	if e.RelayOnly {
		total := 0
		for _, rec := range r.j.Query(func(rec journal.Record) bool {
			return rec.Kind == journal.IceEvent && rec.Text == "candidates"
		}) {
			data, _ := rec.Data.(map[string]any)
			types := map[string]int{}
			switch t := data["types"].(type) {
			case map[string]int: // recorded in this process
				types = t
			case map[string]any: // forwarded from a remote hub as JSON
				for k, v := range t {
					types[k] = toInt(v)
				}
			}
			for typ, n := range types {
				total += n
				if typ != "relay" {
					fails = append(fails, fmt.Sprintf("player %d offered %d %q candidate(s) with relay forced", rec.UID, n, typ))
				}
			}
		}
		if total == 0 {
			fails = append(fails, "no ICE candidates were exchanged")
		}
	}
	if e.PeerStats != nil {
		fails = append(fails, r.checkPeerStats(*e.PeerStats)...)
	}
	return fails
}

// checkPeerStats reads each link's last fakegame PeerStats report:
// PeerStats peer sent answered heard avgRttMicros maxRttMicros.
func (r *runner) checkPeerStats(e PeerStatsExpect) []string {
	type link struct{ from, to int }
	last := map[link][]int32{}
	for _, rec := range r.j.Query(Match{Cmd: "PeerStats"}.matches) {
		vals := make([]int32, 0, len(rec.Args))
		for _, a := range rec.Args {
			v, _ := a.(int32)
			vals = append(vals, v)
		}
		if len(vals) >= 6 {
			last[link{rec.UID, int(vals[0])}] = vals
		}
	}
	var fails []string
	players := r.l.Players()
	for _, from := range players {
		for _, to := range players {
			if from == to {
				continue
			}
			v, ok := last[link{from, to}]
			if !ok {
				fails = append(fails, fmt.Sprintf("no PeerStats from %d about %d", from, to))
				continue
			}
			sent, answered := float64(v[1]), float64(v[2])
			avg := time.Duration(v[4]) * time.Microsecond
			loss := 0.0
			if sent > 0 {
				loss = 1 - answered/sent
			}
			tag := fmt.Sprintf("link %d->%d (sent %d, answered %d, avg rtt %s, loss %.1f%%)",
				from, to, v[1], v[2], avg, 100*loss)
			if int(v[2]) < e.MinAnswered {
				fails = append(fails, tag+fmt.Sprintf(": answered < %d", e.MinAnswered))
			}
			if e.MinAvgRTT > 0 && avg < e.MinAvgRTT {
				fails = append(fails, tag+": avg rtt below "+e.MinAvgRTT.String())
			}
			if e.MaxAvgRTT > 0 && avg > e.MaxAvgRTT {
				fails = append(fails, tag+": avg rtt above "+e.MaxAvgRTT.String())
			}
			if e.MaxLoss != nil && loss > *e.MaxLoss {
				fails = append(fails, tag+fmt.Sprintf(": loss above %.1f%%", 100**e.MaxLoss))
			}
			if e.MinLoss > 0 && loss < e.MinLoss {
				fails = append(fails, tag+fmt.Sprintf(": loss below %.1f%%", 100*e.MinLoss))
			}
		}
	}
	return fails
}

// echo prints journal records worth watching live.
func (r *runner) echo(rec journal.Record) {
	if line, ok := r.format(rec, r.opts.Verbose); ok {
		fmt.Fprintln(r.out, line)
	}
}

// echoAlways prints a record regardless of verbosity (console "tail").
func (r *runner) echoAlways(rec journal.Record) {
	line, _ := r.format(rec, true)
	fmt.Fprintln(r.out, line)
}

func (r *runner) format(rec journal.Record, verbose bool) (string, bool) {
	if !verbose {
		switch rec.Kind {
		case journal.RelayStats, journal.TurnPerm, journal.TurnChannel, journal.IceLogs:
			return "", false
		}
		if rec.Command == "PeerStats" {
			return "", false
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %-16s", rec.Time.Format("15:04:05.000"), rec.Kind)
	if rec.UID != 0 {
		fmt.Fprintf(&b, " p%d", rec.UID)
	}
	if rec.Peer != 0 {
		fmt.Fprintf(&b, "->p%d", rec.Peer)
	}
	if rec.Command != "" {
		b.WriteString(" " + gpgnet.Message{Command: rec.Command, Args: rec.Args}.String())
	}
	if rec.Text != "" {
		b.WriteString(" " + rec.Text)
	}
	if rec.Data != nil && (verbose || rec.Kind == journal.ProcExit || rec.Kind == journal.Warn) {
		if raw, err := json.Marshal(rec.Data); err == nil && len(raw) < 400 {
			b.WriteString(" " + string(raw))
		}
	}
	return b.String(), true
}

// toInt reads a number that may have crossed JSON (float64) or not (int).
func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return -1
}
