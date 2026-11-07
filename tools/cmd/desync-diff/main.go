// desync-diff compares desync dumps from one game (desync_*.zip, written by the engine's desync
// recorder, issue #216, or the .tar.gz copy it uploads) and prints the first value that differs;
// it also rebuilds a side nobody sent from a replay, and serves as the desync server's dump receiver.
// Go with the standard library only, so the k8s manifest can build it from a ConfigMap.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const usage = `usage: desync-diff [compare] A.zip B.zip [C.zip ...] [-C LINES] [--states N] [--force]
       desync-diff rebuild A.zip --exe HEADLESS.exe --replay FILE --init FILE [--out DIR]
                   [--timeout SECONDS] [--no-compare] [-- ENGINE ARGS...]
       desync-diff serve [--host 127.0.0.1] [--port 4319] [--prefix /dumps] [--out DIR]
                   [--token T] [--read-token R] [--max-mb 64]

compare (the default) runs four steps, each dump against the first:
  1. header: build, architecture, game version, sim fixes, map, game mods, switches, /sse2 and
     the floating-point registers
  2. hashes: the last beat every player's hash matched, the first where any differs, and who
     shares which hash there
  3. beat logs: from the last agreed beat on, the first line that differs, with the beat, the
     entity (id, blueprint, army) or army and the field it is about
  4. state.txt: entities that differ, entities on one side only, the first differences
  -C, --context N   lines of context (10)
  --states N        state differences to print (20)
  --force           compare dumps from different games

rebuild plays a replay in headless with the recorder on and /desyncdumpbeat set to A's dump
beat, so the side of a desync that sent no dump can be rebuilt on that player's build; then it
compares the new dump with A. This only shows differences that come from the build, the
architecture or a switch (each build replays its own way every time), not memory corruption or
hardware faults. --out is the run's folder (default rebuilt/ next to A), --timeout the seconds
to wait for the dump (1800); the arguments after -- go to the engine. -C, --states and --force
apply to its compare.

serve receives the dumps games upload (telemetry_DumpEndpoint), stores them per game, writes the
compare report as report.txt once two armies' dumps are in, and serves them back to holders of
the read token (docs/DESYNC_DIAGNOSTICS.md). --token and --read-token default to the
FAF_UPLOAD_TOKEN and FAF_READ_TOKEN environment variables.

Exit code: 0 nothing differs, 1 a difference was found, 2 invalid input.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	var engineArgs []string
	for i, arg := range argv {
		if arg == "--" { // everything after `--` goes to the engine untouched
			engineArgs = append([]string{}, argv[i+1:]...)
			argv = argv[:i]
			break
		}
	}
	command := "compare"
	if len(argv) > 0 {
		switch argv[0] {
		case "compare", "rebuild", "serve":
			command, argv = argv[0], argv[1:]
		case "-h", "--help":
			fmt.Print(usage)
			return 0
		}
	}
	switch command {
	case "serve":
		return runServe(argv)
	case "rebuild":
		return runRebuild(argv, engineArgs)
	}
	return runCompare(argv)
}

// option describes one command-line option: its spellings and whether it takes a value.
type option struct {
	names []string
	value bool
}

// parseArgs splits args into option values (by first name) and positionals, the way argparse
// reads them: options anywhere, "--name value", "--name=value" and "-Cvalue".
func parseArgs(args []string, options []option) (map[string]string, []string, error) {
	values := map[string]string{}
	var positionals []string
	find := func(name string) *option {
		for i := range options {
			for _, n := range options[i].names {
				if n == name {
					return &options[i]
				}
			}
		}
		return nil
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' || isNumber(arg) {
			positionals = append(positionals, arg)
			continue
		}
		name, value, inline := arg, "", false
		if strings.HasPrefix(arg, "--") {
			name, value, inline = strings.Cut(arg, "=")
		} else if len(arg) > 2 {
			name, value, inline = arg[:2], arg[2:], true
		}
		opt := find(name)
		if opt == nil {
			return nil, nil, fmt.Errorf("unrecognized arguments: %s", arg)
		}
		if !opt.value {
			if inline {
				return nil, nil, fmt.Errorf("argument %s: ignored explicit argument %s", name, pyRepr(value))
			}
			values[opt.names[0]] = "true"
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("argument %s: expected one argument", strings.Join(opt.names, "/"))
			}
			i++
			value = args[i]
		}
		values[opt.names[0]] = value
	}
	return values, positionals, nil
}

func isNumber(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// intOption reads an integer option with a default.
func intOption(values map[string]string, name string, fallback int) (int, error) {
	text, ok := values[name]
	if !ok {
		return fallback, nil
	}
	n, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("argument %s: invalid int value: %s", name, pyRepr(text))
	}
	return n, nil
}

var compareOptions = []option{
	{names: []string{"-C", "--context"}, value: true},
	{names: []string{"--states"}, value: true},
	{names: []string{"--force"}},
	{names: []string{"-h", "--help"}},
}

// usageError prints the usage lines (not the whole help) and the error, exit 2.
func usageError(err error) int {
	fmt.Fprint(os.Stderr, usage[:strings.Index(usage, "\n\n")+1])
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	return 2
}

// reportOptions reads -C, --states and --force.
func reportOptions(values map[string]string) (int, int, bool, error) {
	context, err := intOption(values, "-C", 10)
	if err != nil {
		return 0, 0, false, err
	}
	states, err := intOption(values, "--states", 20)
	if err != nil {
		return 0, 0, false, err
	}
	return context, states, values["--force"] != "", nil
}

func runCompare(args []string) int {
	values, paths, err := parseArgs(args, compareOptions)
	if err != nil {
		return usageError(err)
	}
	if values["-h"] != "" {
		fmt.Print(usage)
		return 0
	}
	context, states, force, err := reportOptions(values)
	if err != nil {
		return usageError(err)
	}
	if len(paths) == 0 {
		return usageError(fmt.Errorf("the following arguments are required: dumps"))
	}
	text, code := compareDumps(paths, os.ReadFile, context, states, force)
	printReport(text, code)
	return code
}

// printReport writes a report to stdout; on exit code 2 its last line, the error, goes to stderr.
func printReport(text string, code int) {
	if code != 2 {
		fmt.Print(text)
		return
	}
	if cut := strings.LastIndex(strings.TrimSuffix(text, "\n"), "\n"); cut >= 0 {
		fmt.Print(text[:cut+1])
		text = text[cut+1:]
	}
	fmt.Fprint(os.Stderr, text)
}
