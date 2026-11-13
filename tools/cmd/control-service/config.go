package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the service's configuration file (YAML). Roles, tournaments and hosts live here only; the file is read
// again on SIGHUP or POST /api/v1/admin/reload.
type Config struct {
	Listen     string `yaml:"listen"`
	PublicURL  string `yaml:"public_url"`  // where browsers reach this service; the cookie is Secure when it is https
	CORSOrigin string `yaml:"cors_origin"` // a web UI served from another origin (e.g. Vite's dev server)
	// AdminTokenFile holds a bearer token with the admin role, for scripts (at least 16 characters).
	AdminTokenFile string     `yaml:"admin_token_file"`
	OIDC           OIDCConfig `yaml:"oidc"`
	Roles          struct {
		Admins     []int `yaml:"admins"`     // FAF user ids
		Organisers []int `yaml:"organisers"` // may run organised lobbies of any tournament
	} `yaml:"roles"`
	Tournaments   []Tournament `yaml:"tournaments"`
	Hosts         []HostConfig `yaml:"hosts"`
	PlayerHosting bool         `yaml:"player_hosting"` // signed-in players may ask a host for a game of their own
	SessionHours  float64      `yaml:"session_hours"`
	PollSeconds   float64      `yaml:"poll_seconds"`
	KeyPrefix     string       `yaml:"key_prefix"` // Redis key prefix

	dir          string // the config file's folder: relative file names are read from there
	adminToken   string
	clientSecret string
}

// OIDCConfig is the OpenID provider and this service's registration with it.
type OIDCConfig struct {
	Issuer           string   `yaml:"issuer"` // e.g. https://hydra.faforever.com/
	ClientID         string   `yaml:"client_id"`
	ClientSecretFile string   `yaml:"client_secret_file"` // empty: a public client (PKCE only)
	RedirectURL      string   `yaml:"redirect_url"`       // default <public_url>/auth/callback
	Scopes           []string `yaml:"scopes"`             // default openid, public_profile
	// AcceptAccessTokens lets a client send a FAF access token as Authorization: Bearer (the lobby server's check:
	// signature from the provider's JWKS, issuer, expiry); RequiredScope, when set, must be in its scp.
	AcceptAccessTokens bool   `yaml:"accept_access_tokens"`
	RequiredScope      string `yaml:"required_scope"`
}

// Tournament is an allowlist: who may play in and watch its organised lobbies, and who organises them.
type Tournament struct {
	ID         string `yaml:"id" json:"id"`
	Name       string `yaml:"name" json:"name"`
	Organisers []int  `yaml:"organisers" json:"organisers"`
	Players    []int  `yaml:"players" json:"players"`
	Observers  []int  `yaml:"observers" json:"observers"`
}

// HostConfig is one server-host.
type HostConfig struct {
	Name      string `yaml:"name"`
	URL       string `yaml:"url"` // e.g. http://203.0.113.5:27180
	TokenFile string `yaml:"token_file"`
	Region    string `yaml:"region"`

	token string
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.dir = filepath.Dir(path)
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) file(name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(c.dir, name)
}

func readSecret(path string, min int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if len(s) < min {
		return "", fmt.Errorf("%s holds fewer than %d characters", path, min)
	}
	return s, nil
}

// check fills defaults, reads the token files and refuses what can't work.
func (c *Config) check() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:27190"
	}
	if c.SessionHours <= 0 {
		c.SessionHours = 12
	}
	if c.PollSeconds <= 0 {
		c.PollSeconds = 2
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = "faf-control:"
	}
	if c.PublicURL == "" {
		c.PublicURL = "http://" + c.Listen
	}
	pu, err := url.Parse(c.PublicURL)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		return fmt.Errorf("public_url %q isn't an http(s) URL", c.PublicURL)
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	if c.CORSOrigin != "" {
		cu, err := url.Parse(c.CORSOrigin)
		if err != nil || cu.Host == "" || cu.Path != "" {
			return fmt.Errorf("cors_origin %q isn't an origin (scheme://host[:port])", c.CORSOrigin)
		}
	}
	o := &c.OIDC
	if o.Issuer == "" || o.ClientID == "" {
		return errors.New("oidc needs issuer and client_id")
	}
	if o.RedirectURL == "" {
		o.RedirectURL = c.PublicURL + "/auth/callback"
	}
	if o.ClientSecretFile != "" {
		var err error
		if c.clientSecret, err = readSecret(c.file(o.ClientSecretFile), 1); err != nil {
			return fmt.Errorf("oidc client_secret_file: %w", err)
		}
	}
	if c.AdminTokenFile != "" {
		var err error
		if c.adminToken, err = readSecret(c.file(c.AdminTokenFile), 16); err != nil {
			return fmt.Errorf("admin_token_file: %w", err)
		}
	}
	if len(o.Scopes) == 0 {
		o.Scopes = []string{"openid", "public_profile"}
	}
	if !slices.Contains(o.Scopes, "openid") {
		return errors.New("oidc scopes must include openid")
	}
	seen := map[string]bool{}
	for i := range c.Tournaments {
		t := &c.Tournaments[i]
		if !nameRe.MatchString(t.ID) || seen["t"+t.ID] {
			return fmt.Errorf("tournament id %q: lowercase letters, digits and dashes, unique", t.ID)
		}
		seen["t"+t.ID] = true
		if t.Name == "" {
			t.Name = t.ID
		}
	}
	for i := range c.Hosts {
		h := &c.Hosts[i]
		if !nameRe.MatchString(h.Name) || seen["h"+h.Name] {
			return fmt.Errorf("host name %q: lowercase letters, digits and dashes, unique", h.Name)
		}
		seen["h"+h.Name] = true
		u, err := url.Parse(h.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("host %s: url %q isn't an http(s) URL", h.Name, h.URL)
		}
		h.URL = strings.TrimRight(h.URL, "/")
		if h.TokenFile == "" {
			return fmt.Errorf("host %s needs token_file (its server-host --token-file)", h.Name)
		}
		if h.token, err = readSecret(c.file(h.TokenFile), 16); err != nil {
			return fmt.Errorf("host %s: %w", h.Name, err)
		}
	}
	return nil
}

func (c *Config) tournament(id string) *Tournament {
	for i := range c.Tournaments {
		if c.Tournaments[i].ID == id {
			return &c.Tournaments[i]
		}
	}
	return nil
}

func (c *Config) host(name string) *HostConfig {
	for i := range c.Hosts {
		if c.Hosts[i].Name == name {
			return &c.Hosts[i]
		}
	}
	return nil
}

func (c *Config) sessionTTL() time.Duration {
	return time.Duration(c.SessionHours * float64(time.Hour))
}
func (c *Config) pollInterval() time.Duration {
	return time.Duration(c.PollSeconds * float64(time.Second))
}

// Principal is who a request is from.
type Principal struct {
	UID   int    `json:"uid"` // FAF user id; 0 for the admin token
	Name  string `json:"name"`
	Admin bool   `json:"-"`
	// Organiser is the global role (any tournament); per-tournament organisers are in each Tournament.
	Organiser bool   `json:"-"`
	Via       string `json:"via"` // session, access_token or admin_token
}

// principal gives a signed-in FAF user their roles from the configuration.
func (c *Config) principal(uid int, name, via string) Principal {
	return Principal{UID: uid, Name: name, Via: via, Admin: slices.Contains(c.Roles.Admins, uid),
		Organiser: slices.Contains(c.Roles.Organisers, uid)}
}

// Roles lists a principal's roles: admin, organiser (globally or of at least one tournament), player (every FAF
// user).
func (c *Config) roles(p Principal) []string {
	r := []string{}
	if p.Admin {
		r = append(r, "admin")
	}
	if p.Organiser || p.Admin {
		r = append(r, "organiser")
	} else if p.UID != 0 {
		for _, t := range c.Tournaments {
			if slices.Contains(t.Organisers, p.UID) {
				r = append(r, "organiser")
				break
			}
		}
	}
	if p.UID != 0 {
		r = append(r, "player")
	}
	return r
}

// canOrganise: may p run organised lobbies of tournament t ("" is a lobby outside any tournament: admins and global
// organisers only).
func (c *Config) canOrganise(p Principal, tournament string) bool {
	if p.Admin || p.Organiser {
		return true
	}
	if tournament == "" || p.UID == 0 {
		return false
	}
	t := c.tournament(tournament)
	return t != nil && slices.Contains(t.Organisers, p.UID)
}
