// Command rtt-probe measures this machine's ping to dedicated-server hosts (plan WPR.16): it sends a few UDP probes to
// each host's RTT echo (server-host --rtt-echo) and prints the median, the spread and the loss. With --control it takes
// the hosts from the control service and reports the result there in the signed-in player's name, so that lobbies
// made with "placement": "ping" go to the host whose worst player ping is lowest.
//
//	rtt-probe 203.0.113.5:27180 eu-2=203.0.113.6:27180
//	rtt-probe --control https://control.example.org --token-file faf-access.token
//
// docs/CONTROL_SERVICE.md describes the endpoints.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"faf-main/tools/rttprobe"
)

func main() {
	control := flag.String("control", "", "the control service's URL: probe its hosts and report the result")
	token := flag.String("token", "", "a FAF access token for the control service")
	tokenFile := flag.String("token-file", "", "a file holding the FAF access token")
	noReport := flag.Bool("no-report", false, "with --control, only print the result")
	count := flag.Int("n", 10, "probes per host")
	interval := flag.Duration("interval", 50*time.Millisecond, "between two probes to one host")
	timeout := flag.Duration("timeout", time.Second, "how long the last probe's reply is waited for")
	local := flag.String("local", "", "the local address the probes go from (default: the system's choice)")
	asJSON := flag.Bool("json", false, "print the result as JSON")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: rtt-probe [flags] [name=]host:port ...\n       rtt-probe --control <url> --token-file <file> [flags]")
		flag.PrintDefaults()
	}
	flag.Parse()

	targets := []rttprobe.Target{}
	for _, arg := range flag.Args() {
		name, addr, ok := strings.Cut(arg, "=")
		if !ok {
			name, addr = arg, arg
		}
		targets = append(targets, rttprobe.Target{Name: name, Addr: addr})
	}
	var client *controlClient
	if *control != "" {
		tok := strings.TrimSpace(*token)
		if *tokenFile != "" {
			b, err := os.ReadFile(*tokenFile)
			if err != nil {
				fatal(err)
			}
			tok = strings.TrimSpace(string(b))
		}
		if tok == "" {
			fatal(errors.New("--control needs --token or --token-file"))
		}
		client = &controlClient{base: strings.TrimRight(*control, "/"), token: tok, http: &http.Client{Timeout: 15 * time.Second}}
		hosts, err := client.hosts()
		if err != nil {
			fatal(err)
		}
		for _, h := range hosts {
			if h.RTTEcho == "" {
				fmt.Fprintf(os.Stderr, "%s: no RTT echo, skipped\n", h.Name)
				continue
			}
			targets = append(targets, rttprobe.Target{Name: h.Name, Addr: h.RTTEcho})
		}
	}
	if len(targets) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	opts := rttprobe.Options{Count: *count, Interval: *interval, Timeout: *timeout, Local: *local}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Count)*opts.Interval+opts.Timeout+10*time.Second)
	defer cancel()
	results := rttprobe.ProbeAll(ctx, targets, opts)

	var report any
	if client != nil && !*noReport {
		var err error
		if report, err = client.report(results); err != nil {
			fatal(err)
		}
	}
	if *asJSON {
		out := map[string]any{"results": results}
		if report != nil {
			out["reported"] = report
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(tw, "host\techo\treceived\tloss %\tmedian ms\tmin ms\tmax ms\t")
	for _, r := range results {
		if !r.Reached() {
			fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%.0f\t-\t-\t-\t%s\n", r.Name, r.Addr, r.Received, r.Sent, r.LossPct, r.Error)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%.0f\t%.1f\t%.1f\t%.1f\t\n", r.Name, r.Addr, r.Received, r.Sent, r.LossPct, r.MedianMs, r.MinMs, r.MaxMs)
	}
	_ = tw.Flush()
	if report != nil {
		fmt.Printf("reported to %s\n", client.base)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "rtt-probe:", err)
	os.Exit(1)
}

type controlClient struct {
	base, token string
	http        *http.Client
}

type controlHost struct {
	Name      string `json:"name"`
	Region    string `json:"region"`
	RTTEcho   string `json:"rtt_echo"`
	Reachable bool   `json:"reachable"`
}

func (c *controlClient) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var doc struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &doc)
	if resp.StatusCode != http.StatusOK || !doc.OK {
		if doc.Error == "" {
			doc.Error = strings.TrimSpace(string(b))
		}
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, doc.Error)
	}
	return json.Unmarshal(b, out)
}

// hosts are the control service's hosts with their echo addresses.
func (c *controlClient) hosts() ([]controlHost, error) {
	var doc struct {
		Hosts []controlHost `json:"hosts"`
	}
	err := c.do(http.MethodGet, "/api/v1/rtt/hosts", nil, &doc)
	return doc.Hosts, err
}

// report sends each measured host's median and loss; a host nothing came back from counts as loss 100. Hosts that
// couldn't be probed at all (e.g. an address that doesn't resolve) aren't reported.
func (c *controlClient) report(results []rttprobe.Result) (any, error) {
	rtts := []map[string]any{}
	for _, r := range results {
		switch {
		case r.Reached():
			rtts = append(rtts, map[string]any{"host": r.Name, "ms": r.MedianMs, "loss_pct": r.LossPct})
		case r.Sent > 0:
			rtts = append(rtts, map[string]any{"host": r.Name, "loss_pct": 100})
		}
	}
	if len(rtts) == 0 {
		return nil, errors.New("no host could be probed: nothing to report")
	}
	var doc struct {
		RTT any `json:"rtt"`
	}
	err := c.do(http.MethodPost, "/api/v1/rtt", map[string]any{"rtts": rtts}, &doc)
	return doc.RTT, err
}
