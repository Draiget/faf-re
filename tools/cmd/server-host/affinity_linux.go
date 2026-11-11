//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// startPinned starts cmd with its CPU mask set to cpus. The fork happens on a thread that holds
// that mask, so the child and every thread it makes inherit it; the mask is set on the child again
// after the start, and the thread's own mask is put back.
func startPinned(cmd *exec.Cmd, cpus []int) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if len(cpus) == 0 {
		return cmd.Start()
	}
	var set unix.CPUSet
	for _, c := range cpus {
		set.Set(c)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var old unix.CPUSet
	if err := unix.SchedGetaffinity(0, &old); err != nil {
		return fmt.Errorf("reading this thread's CPU mask: %w", err)
	}
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		return fmt.Errorf("CPUs %v: %w", cpus, err)
	}
	err := cmd.Start()
	_ = unix.SchedSetaffinity(0, &old)
	if err != nil {
		return err
	}
	_ = unix.SchedSetaffinity(cmd.Process.Pid, &set)
	return nil
}

// allowedCPUs is what the kernel says the process may run on (Cpus_allowed_list), for the report.
func allowedCPUs(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Cpus_allowed_list:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// stopProcess asks the lobby's server to end (SIGTERM to its group); kill ends it for good.
func stopProcess(p *os.Process, kill bool) {
	sig := syscall.SIGTERM
	if kill {
		sig = syscall.SIGKILL
	}
	_ = syscall.Kill(-p.Pid, sig)
}
