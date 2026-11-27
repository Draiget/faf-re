// faf-re-setup installs the rebuilt engine from a GitHub release in one step. It checks that FAF's
// client and Forged Alliance are installed and that the engine isn't running, downloads the release
// package for this system, checks it against the release's SHA256SUMS.txt, unpacks it where the engine
// runs from and adds a shortcut. Windows (x64, x86) and Linux (x64). Standard library and x/sys only.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// version is set at build time (-ldflags "-X main.version=<tag>").
var version = "dev"

const usage = `faf-re-setup: installs the rebuilt Forged Alliance engine from its GitHub releases.

usage: faf-re-setup [options]

  --check          run the checks only; install nothing
  --version TAG    install this release instead of the latest one (e.g. 2026.11.015)
  --package FILE   install from a package already downloaded (its SHA256SUMS.txt is used when it
                   sits next to it)
  --x86            (Windows) install the 32-bit engine into FAF's bin folder instead
  --faf-data DIR   FAF's data folder (default: C:\ProgramData\FAForever on Windows; on Linux
                   the client's data folder from ~/.faforever/client.prefs, else ~/.faforever)
  --dir DIR        install into DIR instead of the default (bin_x64 next to FAF's bin on
                   Windows, ~/.local/share/faf-re/engine on Linux)
  --no-shortcut    don't add a desktop or menu shortcut
  --uninstall      remove what an earlier run installed, and its shortcuts
  -y, --yes        don't ask; on Windows, don't wait for Enter at the end
`

type options struct {
	check      bool
	tag        string
	pkg        string
	x86        bool
	fafData    string
	dir        string
	noShortcut bool
	uninstall  bool
	yes        bool
}

func main() {
	var o options
	fs := flag.NewFlagSet("faf-re-setup", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	fs.BoolVar(&o.check, "check", false, "")
	fs.StringVar(&o.tag, "version", "", "")
	fs.StringVar(&o.pkg, "package", "", "")
	fs.BoolVar(&o.x86, "x86", false, "")
	fs.StringVar(&o.fafData, "faf-data", "", "")
	fs.StringVar(&o.dir, "dir", "", "")
	fs.BoolVar(&o.noShortcut, "no-shortcut", false, "")
	fs.BoolVar(&o.uninstall, "uninstall", false, "")
	fs.BoolVar(&o.yes, "yes", false, "")
	fs.BoolVar(&o.yes, "y", false, "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q\n\n%s", fs.Arg(0), usage)
		os.Exit(2)
	}
	code := run(o)
	if !o.yes {
		pauseIfOwnConsole()
	}
	os.Exit(code)
}

func run(o options) int {
	fmt.Printf("faf-re setup %s\n\n", version)
	sys, err := newSystem(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if o.uninstall {
		if err := uninstall(sys, o); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		return 0
	}

	fmt.Println("Checking this computer:")
	results := runChecks(sys)
	failed := printChecks(results)
	if failed > 0 {
		fmt.Printf("\n%d check(s) failed; nothing was installed. Fix the ones marked [!!] and run setup again.\n", failed)
		return 1
	}
	if o.check {
		fmt.Println("\nAll checks passed. Run setup without --check to install.")
		return 0
	}

	pkg, err := resolvePackage(sys, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nerror:", err)
		return 1
	}
	if m, err := readManifest(sys.installDir); err == nil && m.Version == pkg.tag && !o.yes {
		if !ask(fmt.Sprintf("\n%s is already installed in %s. Install it again?", pkg.tag, sys.installDir), false) {
			return 0
		}
	} else if !o.yes {
		if !ask(fmt.Sprintf("\nInstall %s into %s?", pkg.tag, sys.installDir), true) {
			fmt.Println("Nothing was installed.")
			return 0
		}
	}

	if err := install(sys, o, pkg); err != nil {
		fmt.Fprintln(os.Stderr, "\nerror:", err)
		fmt.Fprintln(os.Stderr, "The previous install, if there was one, was left as it was.")
		return 1
	}
	return 0
}

// ask prints a yes/no question and reads the answer; Enter takes the default.
func ask(question string, def bool) bool {
	hint := " [Y/n] "
	if !def {
		hint = " [y/N] "
	}
	fmt.Print(question + hint)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Println()
		return def
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return def
	case "y", "yes":
		return true
	default:
		return false
	}
}
