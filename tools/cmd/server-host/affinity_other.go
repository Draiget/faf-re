//go:build !linux

package main

import (
	"errors"
	"os"
	"os/exec"
)

// The server runs on Linux only; elsewhere the host agent builds for its tests and starts no lobby
// pinned to CPUs.
func startPinned(cmd *exec.Cmd, cpus []int, nodes []int) (string, error) {
	if len(cpus) > 0 {
		return "", errors.New("pinning a lobby to CPUs needs Linux")
	}
	return "", cmd.Start()
}

func allowedCPUs(int) string { return "" }

func stopProcess(p *os.Process, kill bool) {
	if kill {
		_ = p.Kill()
		return
	}
	_ = p.Signal(os.Interrupt)
}
