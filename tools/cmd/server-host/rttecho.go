package main

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"faf-main/tools/rttprobe"
)

// rttEcho answers players' RTT probes (plan WPR.16; format in tools/rttprobe) on one UDP address, by default the API's
// port number on the game address. It answers only a well-formed probe, with a reply of the same size, never a reply
// (two echoes can't be made to answer each other), and at most rate replies a second per source address after a burst,
// and globalRate in all, so a spoofed source gets no more than a trickle of 32-byte packets.
type rttEcho struct {
	conn *net.UDPConn

	rate, burst             float64 // per source address
	globalRate, globalBurst float64

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
	global  bucket
	swept   time.Time
	now     func() time.Time

	answered, dropped, limited atomic.Int64
}

type bucket struct {
	tokens float64
	at     time.Time
}

// take refills b to now and takes one token if there is one.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if b.at.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.at).Seconds()*rate)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

const (
	echoRate        = 10.0 // replies a second per source address, after the burst
	echoBurst       = 20.0
	echoGlobalRate  = 2000.0
	echoGlobalBurst = 2000.0
	echoMaxSources  = 100000 // addresses tracked; past it, new sources wait for the next sweep
)

func listenRTTEcho(addr string) (*rttEcho, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	return &rttEcho{conn: c, rate: echoRate, burst: echoBurst, globalRate: echoGlobalRate, globalBurst: echoGlobalBurst,
		buckets: map[netip.Addr]*bucket{}, now: time.Now}, nil
}

func (e *rttEcho) addr() *net.UDPAddr { return e.conn.LocalAddr().(*net.UDPAddr) }

func (e *rttEcho) close() error { return e.conn.Close() }

// allow takes a token from the source's bucket and the global one; idle sources are swept every minute.
func (e *rttEcho) allow(src netip.Addr) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	if now.Sub(e.swept) > time.Minute {
		for a, b := range e.buckets {
			if now.Sub(b.at).Seconds()*e.rate >= e.burst { // full again: forgetting it changes nothing
				delete(e.buckets, a)
			}
		}
		e.swept = now
	}
	b := e.buckets[src]
	if b == nil {
		if len(e.buckets) >= echoMaxSources {
			return false
		}
		b = &bucket{}
		e.buckets[src] = b
	}
	if !b.take(now, e.rate, e.burst) {
		return false
	}
	return e.global.take(now, e.globalRate, e.globalBurst)
}

// serve answers probes until the socket closes.
func (e *rttEcho) serve() {
	// Room for any ordinary datagram, so a larger one is read whole and dropped by its size (Windows refuses to cut a
	// datagram short; a larger one fails the read and is skipped).
	buf := make([]byte, 2048)
	for {
		n, from, err := e.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		reply := rttprobe.Reply(buf[:n])
		if reply == nil {
			e.dropped.Add(1)
			continue
		}
		if !e.allow(from.Addr().Unmap()) {
			e.limited.Add(1)
			continue
		}
		if _, err := e.conn.WriteToUDPAddrPort(reply, from); err == nil {
			e.answered.Add(1)
		}
	}
}

// rttEchoAddress turns --rtt-echo into the address to listen on: "" is the API's port number on the game address,
// "off" none, a bare port that port on the game address, else host:port as given.
func rttEchoAddress(flagValue, apiListen, gameIP string) (string, error) {
	switch flagValue {
	case "off", "none", "0":
		return "", nil
	case "":
		_, port, err := net.SplitHostPort(apiListen)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(gameIP, port), nil
	}
	if p, err := strconv.Atoi(flagValue); err == nil {
		if p < 1 || p > 65535 {
			return "", errors.New("--rtt-echo port out of range")
		}
		return net.JoinHostPort(gameIP, flagValue), nil
	}
	if _, _, err := net.SplitHostPort(flagValue); err != nil {
		return "", err
	}
	return flagValue, nil
}

// startRTTEcho listens and serves; the public address is publicHost with the echo's port.
func startRTTEcho(listen, publicHost string) (*rttEcho, string) {
	e, err := listenRTTEcho(listen)
	if err != nil {
		log.Fatalf("RTT echo on udp %s: %v (--rtt-echo off turns it off)", listen, err)
	}
	go e.serve()
	public := net.JoinHostPort(publicHost, strconv.Itoa(e.addr().Port))
	log.Printf("RTT echo on udp %s (players probe %s)", e.addr(), public)
	return e, public
}
