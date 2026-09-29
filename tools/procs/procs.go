// Package procs starts the processes of a run (game instances, ICE adapters)
// and guarantees they die with it: on Windows every child is placed in a job
// object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, so even a crashed or killed
// mpemu leaves no game running.
package procs

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Spec describes one process.
type Spec struct {
	Name string
	Exe  string
	Dir  string
	Args []string
	// Output receives stdout+stderr; empty discards them.
	Output string
	Env    []string
}

// Process is a started child.
type Process struct {
	Name string
	cmd  *exec.Cmd
	out  *os.File

	done     chan struct{}
	mu       sync.Mutex
	exitCode int
	exitErr  error
	killed   bool
}

// Start launches spec and adds it to job (which may be nil).
func Start(spec Spec, job *Job) (*Process, error) {
	cmd := exec.Command(spec.Exe, spec.Args...)
	cmd.Dir = spec.Dir
	if len(spec.Env) > 0 {
		cmd.Env = append(os.Environ(), spec.Env...)
	}
	var out *os.File
	if spec.Output != "" {
		f, err := os.Create(spec.Output)
		if err != nil {
			return nil, err
		}
		out = f
		cmd.Stdout = f
		cmd.Stderr = f
	}
	if err := cmd.Start(); err != nil {
		if out != nil {
			_ = out.Close()
		}
		return nil, fmt.Errorf("start %s: %w", spec.Name, err)
	}
	p := &Process{Name: spec.Name, cmd: cmd, out: out, done: make(chan struct{}), exitCode: -1}
	if job != nil {
		if err := job.Assign(cmd.Process.Pid); err != nil {
			fmt.Fprintf(os.Stderr, "mpemu: warning: %s (pid %d) is not in the kill-on-exit job: %v\n",
				spec.Name, cmd.Process.Pid, err)
		}
	}
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.exitErr = err
		if cmd.ProcessState != nil {
			p.exitCode = cmd.ProcessState.ExitCode()
		}
		p.mu.Unlock()
		if out != nil {
			_ = out.Close()
		}
		close(p.done)
	}()
	return p, nil
}

// Pid is the OS process id.
func (p *Process) Pid() int { return p.cmd.Process.Pid }

// Done is closed when the process has exited.
func (p *Process) Done() <-chan struct{} { return p.done }

// Exited reports whether the process is gone.
func (p *Process) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// ExitCode is the exit status, -1 while running or when unknown.
func (p *Process) ExitCode() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitCode
}

// Killed reports whether mpemu terminated the process itself.
func (p *Process) Killed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.killed
}

// Kill terminates the process (TerminateProcess on Windows) and waits for it.
func (p *Process) Kill() {
	if p.Exited() {
		return
	}
	p.mu.Lock()
	p.killed = true
	p.mu.Unlock()
	_ = p.cmd.Process.Kill()
	<-p.done
}

// CommandLine renders exe + args as one Windows command line, e.g. for
// pasting into Visual Studio's Debugging > Command Arguments.
func CommandLine(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quote(exe))
	for _, a := range args {
		parts = append(parts, quote(a))
	}
	return strings.Join(parts, " ")
}

// Arguments renders only the arguments.
func Arguments(args []string) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, quote(a))
	}
	return strings.Join(parts, " ")
}

func quote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
