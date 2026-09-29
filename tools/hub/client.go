package hub

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"faf-main/tools/relay"
)

// Client talks to a hub. Base is the hub's root URL, e.g.
// https://faftest.zontwelg.net:8443 (a DNS name, never an address baked into
// configuration).
type Client struct {
	Base      string
	secret    string
	transport *http.Transport // verifies the hub by its secret-derived key
	short     *http.Client    // requests
	stream    *http.Client    // event streams: no overall timeout

	gwOnce sync.Once
	gw     *http.Server
	gwURL  string
	gwErr  error
}

// NewClient creates a client.
func NewClient(base, secret string) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = ClientTLS(secret)
	return &Client{
		Base:      strings.TrimRight(base, "/"),
		secret:    secret,
		transport: tr,
		short:     &http.Client{Timeout: 15 * time.Second, Transport: tr},
		stream:    &http.Client{Transport: tr},
	}
}

// Gateway returns a URL the ICE adapter can use as its API root. The adapter
// trusts only public certificate authorities and the hub proves itself with
// the secret-derived key, so for an https hub the gateway serves the
// icebreaker API on a loopback port, checks the hub as the client does and
// relays each request (event streams unbuffered). One gateway serves every
// seat of the process. A plain-http hub needs none.
func (c *Client) Gateway() (string, error) {
	c.gwOnce.Do(func() {
		target, err := url.Parse(c.Base)
		if err != nil {
			c.gwErr = err
			return
		}
		if target.Scheme != "https" {
			c.gwURL = c.Base
			return
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			c.gwErr = fmt.Errorf("hub gateway: %w", err)
			return
		}
		proxy := &httputil.ReverseProxy{
			Rewrite:       func(r *httputil.ProxyRequest) { r.SetURL(target) },
			Transport:     c.transport,
			FlushInterval: -1,
		}
		mux := http.NewServeMux()
		mux.Handle("/session/", proxy) // the icebreaker API only; never the hub's control routes
		c.gw = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = c.gw.Serve(ln) }()
		c.gwURL = "http://" + ln.Addr().String()
	})
	return c.gwURL, c.gwErr
}

// Close stops the gateway, if one was started.
func (c *Client) Close() {
	if c.gw != nil {
		_ = c.gw.Close()
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.short.Do(req)
	if err != nil {
		return fmt.Errorf("hub %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("hub %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Send posts one envelope into a mailbox.
func (c *Client) Send(ctx context.Context, box string, env Envelope) error {
	return c.do(ctx, http.MethodPost, "/hub/send/"+box, env, nil)
}

// Info is the hub's self-description.
type Info struct {
	PublicHost string `json:"publicHost"`
	RelayPorts []int  `json:"relayPorts"`
}

// Info fetches the hub's self-description (and checks the secret).
func (c *Client) Info(ctx context.Context) (Info, error) {
	var info Info
	err := c.do(ctx, http.MethodGet, "/hub/info", nil, &info)
	return info, err
}

// Agents lists the agents the hub knows.
func (c *Client) Agents(ctx context.Context) ([]AgentInfo, error) {
	var out []AgentInfo
	err := c.do(ctx, http.MethodGet, "/hub/agents", nil, &out)
	return out, err
}

// Watch forwards a game's ICE and TURN records to a mailbox.
func (c *Client) Watch(ctx context.Context, game uint64, box string) error {
	return c.do(ctx, http.MethodPost, "/hub/watch", map[string]any{"game": game, "box": box}, nil)
}

// RelayLink creates (or finds) the relay link a<->b of a run; it returns the
// hub port a sends to in order to reach b, and the one b sends to for a.
func (c *Client) RelayLink(ctx context.Context, run, box string, a, b int) (portForA, portForB int, err error) {
	var out struct {
		PortForA int `json:"portForA"`
		PortForB int `json:"portForB"`
	}
	err = c.do(ctx, http.MethodPost, "/hub/relay/"+run+"/links", map[string]any{"box": box, "A": a, "B": b}, &out)
	return out.PortForA, out.PortForB, err
}

// RelayImpair changes a relay link's impairment.
func (c *Client) RelayImpair(ctx context.Context, run string, from, to int, imp relay.Impairment, both bool) error {
	return c.do(ctx, http.MethodPost, "/hub/relay/"+run+"/impair",
		map[string]any{"From": from, "To": to, "Both": both, "Impairment": imp}, nil)
}

// RelayIsolate cuts or restores every link of one player.
func (c *Client) RelayIsolate(ctx context.Context, run string, uid int, blocked bool) error {
	return c.do(ctx, http.MethodPost, "/hub/relay/"+run+"/isolate", map[string]any{"UID": uid, "Blocked": blocked}, nil)
}

// RelayStats returns a run's relay counters.
func (c *Client) RelayStats(ctx context.Context, run string) (map[string]relay.DirStats, error) {
	var out map[string]relay.DirStats
	err := c.do(ctx, http.MethodGet, "/hub/relay/"+run+"/stats", nil, &out)
	return out, err
}

// RelayClose tears a run's relay down.
func (c *Client) RelayClose(ctx context.Context, run string) error {
	return c.do(ctx, http.MethodDelete, "/hub/relay/"+run, nil, nil)
}

// Listen streams a mailbox into fn until ctx ends, reconnecting with backoff.
// connected, when set, is called each time the stream is (re)established.
func (c *Client) Listen(ctx context.Context, box string, fn func(Envelope), connected func()) {
	backoff := 500 * time.Millisecond
	for ctx.Err() == nil {
		err := c.listenOnce(ctx, box, fn, connected)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = 500 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 10*time.Second {
			backoff *= 2
		}
	}
}

func (c *Client) listenOnce(ctx context.Context, box string, fn func(Envelope), connected func()) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/hub/listen/"+box, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hub listen %s: %s", box, resp.Status)
	}
	if connected != nil {
		connected()
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 32<<20)
	for sc.Scan() {
		line := sc.Text()
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue // comments / keepalives
		}
		var env Envelope
		if json.Unmarshal([]byte(data), &env) == nil {
			fn(env)
		}
	}
	return sc.Err()
}
