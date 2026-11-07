package main

// `desync-diff rebuild`: plays the game's replay in headless with the recorder on and
// /desyncdumpbeat at the given dump's beat, waits until the log names the written dump, stops the
// run and compares the new dump with the given one.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var wroteDump = regexp.MustCompile(`Desync recorder: wrote (.+?\.zip)`)

var rebuildOptions = append([]option{
	{names: []string{"--exe"}, value: true},
	{names: []string{"--replay"}, value: true},
	{names: []string{"--init"}, value: true},
	{names: []string{"--out"}, value: true},
	{names: []string{"--timeout"}, value: true},
	{names: []string{"--no-compare"}},
}, compareOptions...)

func runRebuild(args, engineArgs []string) int {
	values, positionals, err := parseArgs(args, rebuildOptions)
	if err != nil {
		return usageError(err)
	}
	if values["-h"] != "" {
		fmt.Print(usage)
		return 0
	}
	var missing []string
	if len(positionals) == 0 {
		missing = append(missing, "dump")
	}
	for _, name := range []string{"--exe", "--replay", "--init"} {
		if values[name] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return usageError(fmt.Errorf("the following arguments are required: %s", strings.Join(missing, ", ")))
	}
	if len(positionals) > 1 {
		return usageError(fmt.Errorf("unrecognized arguments: %s", strings.Join(positionals[1:], " ")))
	}
	context, states, force, err := reportOptions(values)
	if err != nil {
		return usageError(err)
	}
	timeout, err := intOption(values, "--timeout", 1800)
	if err != nil {
		return usageError(err)
	}
	r := &report{}
	code, err := rebuild(r, positionals[0], values["--exe"], values["--replay"], values["--init"], values["--out"],
		time.Duration(timeout)*time.Second, values["--no-compare"] != "", engineArgs, context, states, force)
	if err != nil {
		return failWith(r, err)
	}
	fmt.Print(r.String())
	return code
}

// failWith prints what was reported so far, then the error the way desync_diff.py did.
func failWith(r *report, err error) int {
	fmt.Print(r.String())
	if bad, ok := err.(badInput); ok {
		fmt.Fprintf(os.Stderr, "error: %s\n", bad.text)
	} else {
		fmt.Fprintf(os.Stderr, "error: a dump is damaged (%s)\n", err.Error())
	}
	return 2
}

func rebuild(r *report, dumpPath, exe, replay, initFile, out string, timeout time.Duration, noCompare bool,
	engineArgs []string, context, states int, force bool) (int, error) {
	data, err := os.ReadFile(dumpPath)
	if err != nil {
		return 2, badInput{fmt.Sprintf("%s: not a desync dump (%s)", dumpPath, err)}
	}
	base, err := openDump(dumpPath, data)
	if err != nil {
		return 2, err
	}
	desync, _ := base.header["desync"].(map[string]any)
	beat, isInt := pyInt(desync["dump_beat"])
	if !isInt || beat <= 0 {
		return 2, badInput{dumpPath + " has no dump beat"}
	}
	if out == "" {
		abs, _ := filepath.Abs(dumpPath)
		out = filepath.Join(filepath.Dir(abs), "rebuilt")
	}
	out, _ = filepath.Abs(out)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return 2, err
	}
	logPath := filepath.Join(out, "game.log")
	if _, err := os.Stat(logPath); err == nil {
		if err := os.Remove(logPath); err != nil {
			return 2, err
		}
	}
	command := append([]string{exe, "--replay", replay, "/init", initFile, "/nosound", "/log", logPath,
		"/desyncrecorder", "/desyncdumpbeat", fmt.Sprint(beat)}, engineArgs...)
	r.say("running: " + listToCmdline(command))
	fmt.Print(r.String()) // shown before the run starts
	r.Reset()
	console, err := os.Create(filepath.Join(out, "headless.txt"))
	if err != nil {
		return 2, err
	}
	defer console.Close()
	process := exec.Command(command[0], command[1:]...)
	process.Stdout, process.Stderr = console, console
	if err := process.Start(); err != nil {
		return 2, badInput{fmt.Sprintf("can't run %s (%s)", exe, err)}
	}
	exited := make(chan struct{})
	go func() {
		process.Wait()
		close(exited)
	}()
	written := ""
	deadline := time.Now().Add(timeout)
	for written == "" && time.Now().Before(deadline) {
		if text, err := os.ReadFile(logPath); err == nil {
			if m := wroteDump.FindSubmatch(text); m != nil {
				written = string(m[1])
				break
			}
		}
		select {
		case <-exited:
			// The run ended: one last look at the log, which may have been written as it quit.
			if text, err := os.ReadFile(logPath); err == nil {
				if m := wroteDump.FindSubmatch(text); m != nil {
					written = string(m[1])
				}
			}
			deadline = time.Now()
		case <-time.After(time.Second):
		}
	}
	select {
	case <-exited:
	default:
		process.Process.Kill() // the dump is written; the rest of the replay isn't needed
		<-exited
	}
	if written == "" {
		return 2, badInput{fmt.Sprintf("the replay run wrote no dump (log: %s)", logPath)}
	}
	r.say("wrote: " + written)
	if noCompare {
		return 0, nil
	}
	r.say("")
	return compareInto(r, []string{dumpPath, written}, os.ReadFile, context, states, force)
}

// listToCmdline is Python's subprocess.list2cmdline: how the command line is shown.
func listToCmdline(args []string) string {
	var b strings.Builder
	for _, arg := range args {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		quote := arg == "" || strings.ContainsAny(arg, " \t")
		if quote {
			b.WriteByte('"')
		}
		backslashes := 0
		for _, c := range arg {
			switch c {
			case '\\':
				backslashes++
			case '"':
				b.WriteString(strings.Repeat(`\`, backslashes*2))
				backslashes = 0
				b.WriteString(`\"`)
			default:
				b.WriteString(strings.Repeat(`\`, backslashes))
				backslashes = 0
				b.WriteRune(c)
			}
		}
		b.WriteString(strings.Repeat(`\`, backslashes))
		if quote {
			b.WriteString(strings.Repeat(`\`, backslashes))
			b.WriteByte('"')
		}
	}
	return b.String()
}
