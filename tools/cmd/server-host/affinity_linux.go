//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// startPinned starts cmd with its CPU mask set to cpus and, with one NUMA node given, its memory preferred on that
// node (plan WP17.17). The fork happens on a thread that holds the mask and the memory policy, so the child and every
// thread it makes inherit both; the mask is set on the child again after the start, and the thread's own are put back.
// The memory policy is best effort: where the kernel refuses it (a container without CAP_SYS_NICE), the lobby still
// starts and the refusal comes back as memNote.
func startPinned(cmd *exec.Cmd, cpus []int, nodes []int) (memNote string, err error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if len(cpus) == 0 {
		return "", cmd.Start()
	}
	var set unix.CPUSet
	for _, c := range cpus {
		set.Set(c)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var old unix.CPUSet
	if err := unix.SchedGetaffinity(0, &old); err != nil {
		return "", fmt.Errorf("reading this thread's CPU mask: %w", err)
	}
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		return "", fmt.Errorf("CPUs %v: %w", cpus, err)
	}
	preferred := len(nodes) == 1 && nodes[0] >= 0 && nodes[0] < 64
	if preferred {
		if perr := setMemPolicy(mpolPreferred, uint64(1)<<uint(nodes[0])); perr != nil {
			preferred = false
			memNote = fmt.Sprintf("its memory isn't held to NUMA node %d: the kernel refused the memory policy (%v; in a container, add CAP_SYS_NICE)", nodes[0], perr)
		}
	}
	err = cmd.Start()
	if preferred {
		_ = setMemPolicy(mpolDefault, 0)
	}
	_ = unix.SchedSetaffinity(0, &old)
	if err != nil {
		return memNote, err
	}
	_ = unix.SchedSetaffinity(cmd.Process.Pid, &set)
	return memNote, nil
}

const (
	mpolDefault   = 0
	mpolPreferred = 1
)

// setMemPolicy sets this thread's NUMA memory policy (set_mempolicy(2)); a child forked from it inherits the policy.
func setMemPolicy(mode int, nodemask uint64) error {
	var maskPtr uintptr
	var maxNode uintptr
	if mode != mpolDefault {
		maskPtr = uintptr(unsafe.Pointer(&nodemask))
		maxNode = 65 // the kernel reads maxnode-1 bits: all 64 of the mask
	}
	if _, _, errno := unix.Syscall(unix.SYS_SET_MEMPOLICY, uintptr(mode), maskPtr, maxNode); errno != 0 {
		return errno
	}
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
