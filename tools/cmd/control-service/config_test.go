package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigChecks(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "h.token"), []byte("0123456789abcdef\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "short.token"), []byte("short"), 0o600)
	base := "oidc:\n  issuer: https://hydra.example.org/\n  client_id: c\n"
	cases := map[string]string{
		"":                      base,
		"field bogus not found": base + "bogus: 1\n",
		"needs issuer":          "oidc:\n  client_id: c\n",
		"must include openid":   base + "  scopes: [public_profile]\n",
		"needs token_file":      base + "hosts:\n  - name: a\n    url: http://203.0.113.5:27180\n",
		"fewer than 16":         base + "hosts:\n  - name: a\n    url: http://203.0.113.5:27180\n    token_file: short.token\n",
		"unique":                base + "hosts:\n  - {name: a, url: 'http://203.0.113.5:1', token_file: h.token}\n  - {name: a, url: 'http://203.0.113.6:1', token_file: h.token}\n",
		"isn't an http(s) URL":  base + "hosts:\n  - {name: a, url: 'ftp://x', token_file: h.token}\n",
		"lowercase letters":     base + "tournaments:\n  - id: Big Cup\n",
		"isn't an origin":       base + "cors_origin: http://localhost:5173/app\n",
	}
	for want, text := range cases {
		p := filepath.Join(dir, "c.yaml")
		_ = os.WriteFile(p, []byte(text), 0o600)
		cfg, err := loadConfig(p)
		if want == "" {
			if err != nil {
				t.Fatalf("a minimal configuration: %v", err)
			}
			if cfg.Listen != "127.0.0.1:27190" || cfg.OIDC.RedirectURL != "http://127.0.0.1:27190/auth/callback" ||
				strings.Join(cfg.OIDC.Scopes, " ") != "openid public_profile" || cfg.PollSeconds != 2 {
				t.Fatalf("defaults: %+v", cfg)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", want, err)
		}
	}
}
