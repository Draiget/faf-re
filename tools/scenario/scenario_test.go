package scenario

import (
	"path/filepath"
	"testing"
	"time"
)

// Every shipped scenario must parse (unknown keys are errors) and normalise.
func TestShippedScenarios(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "scenarios", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no scenarios found: %v", err)
	}
	for _, f := range files {
		sc, err := Load(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		cfg := sc.Config
		if sc.Config.Mode == "ice" && cfg.ICE.Adapter == "" {
			cfg.ICE.Adapter = "faf-adapter.exe" // supplied by the command line in real runs
		}
		if err = cfg.Normalize(); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		if len(sc.Steps) == 0 {
			t.Errorf("%s: no steps", f)
		}
		for i, s := range sc.Steps {
			if s.String() == "empty step" {
				t.Errorf("%s: step %d has no action", f, i+1)
			}
		}
	}
}

func TestDurationsAndSelectors(t *testing.T) {
	sc, err := Load(filepath.Join("..", "scenarios", "3p-relay-lag-and-drop.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var link *LinkStep
	for _, s := range sc.Steps {
		if s.Link != nil {
			link = s.Link
		}
	}
	if link == nil || link.Latency != 150*time.Millisecond || link.Jitter != 30*time.Millisecond || link.Loss != 0.03 {
		t.Fatalf("link step decoded as %+v", link)
	}
	if got := (UIDs{Others: true}).Resolve([]int{1, 2, 3}, 1); len(got) != 2 || got[0] != 2 {
		t.Fatalf("others = %v", got)
	}
}
