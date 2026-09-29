package hub

import (
	"fmt"
	"os"
	"strings"
)

// ReadSecret returns the shared hub secret: MPEMU_SECRET, else the first line
// of file (-secret-file / MPEMU_SECRET_FILE). Secrets never come from the
// command line, so they stay out of shell history and process listings.
func ReadSecret(file string) (string, error) {
	if s := strings.TrimSpace(os.Getenv("MPEMU_SECRET")); s != "" {
		return s, nil
	}
	if file == "" {
		return "", nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("secret file: %w", err)
	}
	return strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0]), nil
}
