//go:build !windows && !linux

package main

import "errors"

// macOS and other systems have no release package yet.
func newSystem(o options) (*system, error) {
	return nil, errors.New("setup supports Windows and Linux; this system has no release package yet")
}

func platformChecks(s *system) []check            { return nil }
func writeHint(s *system) []string                { return nil }
func steamRoots() []string                        { return nil }
func freeBytes(dir string) (uint64, error)        { return 0, errors.New("unsupported") }
func engineRunning(exe string) (bool, error)      { return false, nil }
func createShortcuts(s *system) ([]string, error) { return nil, errors.New("unsupported") }
func afterInstall(s *system)                      {}
func pauseIfOwnConsole()                          {}
