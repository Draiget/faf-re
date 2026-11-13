// Package rttprobe measures a player's round-trip time to server hosts (plan WPR.16). Each host answers a fixed-format
// UDP probe on its echo address (server-host --rtt-echo); the prober sends a few probes to each host, matches the
// replies by their sequence number and reports the median, the spread and the loss. The control service places a
// lobby on the host whose worst player ping is lowest; the command rtt-probe and the launcher use this package to
// measure and report.
//
// A probe and its reply are PacketSize bytes:
//
//	0  4  magic "FRTT"
//	4  1  version (1)
//	5  1  kind: 1 probe, 2 reply
//	6  2  zero
//	8  8  session: the prober's random number, the same for all its probes
//	16 8  sequence number
//	24 8  zero
//
// The echo answers a probe with the same bytes and kind 2, never more bytes than it got, and never answers a reply (two
// echoes can't be set to answer each other).
package rttprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	// PacketSize is the only size a probe or reply has.
	PacketSize = 32
	Version    = 1
	KindProbe  = 1
	KindReply  = 2
)

var magic = [4]byte{'F', 'R', 'T', 'T'}

// Encode writes a packet of the given kind.
func Encode(kind byte, session, seq uint64) []byte {
	b := make([]byte, PacketSize)
	copy(b, magic[:])
	b[4], b[5] = Version, kind
	binary.BigEndian.PutUint64(b[8:], session)
	binary.BigEndian.PutUint64(b[16:], seq)
	return b
}

// Parse checks a packet's format: its size, magic, version, a known kind and the zero fields.
func Parse(b []byte) (kind byte, session, seq uint64, ok bool) {
	if len(b) != PacketSize || [4]byte(b[:4]) != magic || b[4] != Version || (b[5] != KindProbe && b[5] != KindReply) ||
		b[6] != 0 || b[7] != 0 || binary.BigEndian.Uint64(b[24:]) != 0 {
		return 0, 0, 0, false
	}
	return b[5], binary.BigEndian.Uint64(b[8:]), binary.BigEndian.Uint64(b[16:]), true
}

// Reply is the echo's answer to a well-formed probe, or nil for anything else (a reply, a malformed packet).
func Reply(b []byte) []byte {
	kind, session, seq, ok := Parse(b)
	if !ok || kind != KindProbe {
		return nil
	}
	return Encode(KindReply, session, seq)
}

// Options says how a host is measured; zero fields take the defaults.
type Options struct {
	Count    int           // probes per host (default 10)
	Interval time.Duration // between two probes to one host (default 50 ms)
	Timeout  time.Duration // how long the last probe's reply is waited for (default 1 s)
	// Local is the address the probes are sent from (an IP, or IP:port); empty lets the system choose.
	Local string
}

func (o Options) withDefaults() Options {
	if o.Count <= 0 {
		o.Count = 10
	}
	if o.Interval <= 0 {
		o.Interval = 50 * time.Millisecond
	}
	if o.Timeout <= 0 {
		o.Timeout = time.Second
	}
	return o
}

// Result is one host's measurement. With no reply at all, the times are 0 and LossPct is 100.
type Result struct {
	Name     string  `json:"name,omitempty"`
	Addr     string  `json:"addr"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"loss_pct"`
	MedianMs float64 `json:"median_ms"`
	MinMs    float64 `json:"min_ms"`
	MaxMs    float64 `json:"max_ms"`
	Error    string  `json:"error,omitempty"`
}

// Reached says whether any probe came back.
func (r Result) Reached() bool { return r.Received > 0 }

// Target is a host to measure.
type Target struct {
	Name string
	Addr string // host:port of its echo
}

// Probe measures one echo address.
func Probe(ctx context.Context, addr string, o Options) Result {
	o = o.withDefaults()
	res := Result{Addr: addr, LossPct: 100}
	d := &net.Dialer{}
	if o.Local != "" {
		local := o.Local
		if _, _, err := net.SplitHostPort(local); err != nil {
			local = net.JoinHostPort(local, "0")
		}
		la, err := net.ResolveUDPAddr("udp", local)
		if err != nil {
			res.Error = fmt.Sprintf("local address: %v", err)
			return res
		}
		d.LocalAddr = la
	}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()
	var sb [8]byte
	if _, err := rand.Read(sb[:]); err != nil {
		res.Error = err.Error()
		return res
	}
	session := binary.BigEndian.Uint64(sb[:])

	var mu sync.Mutex
	sentAt := make([]time.Time, o.Count)
	rtts := make([]time.Duration, o.Count)
	got := make([]bool, o.Count)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		for {
			n, err := conn.Read(buf)
			now := time.Now()
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					return
				}
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				continue // e.g. an ICMP port unreachable reported on Windows: wait for the others
			}
			kind, s, seq, ok := Parse(buf[:n])
			if !ok || kind != KindReply || s != session || seq >= uint64(o.Count) {
				continue
			}
			mu.Lock()
			if !got[seq] && !sentAt[seq].IsZero() {
				got[seq], rtts[seq] = true, now.Sub(sentAt[seq])
			}
			mu.Unlock()
		}
	}()
	for i := 0; i < o.Count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(o.Interval):
			}
		}
		if ctx.Err() != nil {
			break
		}
		mu.Lock()
		sentAt[i] = time.Now()
		mu.Unlock()
		if _, err := conn.Write(Encode(KindProbe, session, uint64(i))); err == nil {
			res.Sent++
		} else if res.Error == "" {
			res.Error = err.Error()
		}
	}
	deadline := time.Now().Add(o.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	<-done

	mu.Lock()
	defer mu.Unlock()
	ms := []float64{}
	for i := range got {
		if got[i] {
			ms = append(ms, float64(rtts[i].Microseconds())/1000)
		}
	}
	res.Received = len(ms)
	if res.Sent > 0 {
		res.LossPct = round1(100 * float64(res.Sent-res.Received) / float64(res.Sent))
	}
	if len(ms) > 0 {
		res.Error = ""
		sort.Float64s(ms)
		res.MinMs, res.MaxMs, res.MedianMs = round1(ms[0]), round1(ms[len(ms)-1]), round1(median(ms))
	} else if res.Error == "" {
		res.Error = fmt.Sprintf("no reply in %v", o.Timeout)
	}
	return res
}

// ProbeAll measures every target at once (one socket each) and answers in the targets' order.
func ProbeAll(ctx context.Context, targets []Target, o Options) []Result {
	out := make([]Result, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := Probe(ctx, t.Addr, o)
			r.Name = t.Name
			out[i] = r
		}()
	}
	wg.Wait()
	return out
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
