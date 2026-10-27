package netfuzz

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Options configures a fuzzing run.
type Options struct {
	// Target is the host's lobby UDP endpoint, "host:port".
	Target string
	// Bind is the local UDP address to send from, "host:port". Empty lets the
	// OS pick. On an isolated host the engine insists on a specific advertised
	// source address, so set this to that address with port 0 (e.g.
	// "192.168.42.77:0") to make the host accept our datagrams.
	Bind string
	// Prime sends one valid CONNECT before the corpus so the host registers a
	// pending connection from our endpoint; without it the per-connection
	// handlers (ANSWER/DATA/ACK/KEEPALIVE/GOODBYE) are dropped as coming from an
	// unknown host and never run.
	Prime bool
	// Delay between datagrams. Zero sends as fast as the socket accepts.
	Delay time.Duration
	// Iterations replays the whole corpus this many times (>=1).
	Iterations int
	// Probe does a liveness CONNECT and waits ProbeWait for any reply from the
	// host, before and after the run.
	Probe bool
	// ProbeWait bounds each liveness probe.
	ProbeWait time.Duration
	// DryRun generates and reports the corpus without opening a socket.
	DryRun bool
	// Gen controls corpus generation.
	Gen GenOptions
	// Logger receives progress lines. Nil discards them.
	Logger *log.Logger
}

// Result summarizes a run. SendErrors rising after datagrams were already
// delivered is itself a signal the host's socket went away (a Windows UDP send
// to a dead endpoint fails with WSAECONNRESET), i.e. a likely crash.
type Result struct {
	Corpus          int    // crafted packets per iteration
	Iterations      int    // iterations actually run
	Sent            int    // datagrams written
	SendErrors      int    // failed writes
	BytesSent       int64  // total bytes put on the wire
	Received        int64  // datagrams received back from the target
	BytesReceived   int64  // total bytes received back
	RespondedBefore bool   // host replied to the pre-run liveness probe
	RespondedAfter  bool   // host replied to the post-run liveness probe
	FirstResponse   []byte // first datagram the host sent back (truncated)
}

func (o *Options) normalize() {
	if o.Iterations < 1 {
		o.Iterations = 1
	}
	if o.ProbeWait <= 0 {
		o.ProbeWait = 2 * time.Second
	}
}

func (o *Options) logf(format string, args ...any) {
	if o.Logger != nil {
		o.Logger.Printf(format, args...)
	}
}

// Run generates the corpus and drives it at the target. It stops early only if
// ctx is cancelled; a crashed host surfaces as a jump in Result.SendErrors and
// RespondedAfter == false, not as an error from Run, because UDP delivery is
// not acknowledged.
func Run(ctx context.Context, opts Options) (Result, error) {
	opts.normalize()
	var res Result

	corpus, err := Generate(opts.Gen)
	if err != nil {
		return res, err
	}
	res.Corpus = len(corpus)
	opts.logf("corpus: %d crafted packets across %v (seed %d)", len(corpus), categoriesOf(corpus), opts.Gen.Seed)

	if opts.DryRun {
		for _, p := range corpus {
			opts.logf("  [%s] %s (%d bytes)", p.Category, p.Name, len(p.Data))
		}
		return res, nil
	}
	if opts.Target == "" {
		return res, errors.New("netfuzz: Target host:port is required")
	}

	target, err := net.ResolveUDPAddr("udp4", opts.Target)
	if err != nil {
		return res, fmt.Errorf("netfuzz: resolve target %q: %w", opts.Target, err)
	}

	var local *net.UDPAddr
	if opts.Bind != "" {
		if local, err = net.ResolveUDPAddr("udp4", opts.Bind); err != nil {
			return res, fmt.Errorf("netfuzz: resolve bind %q: %w", opts.Bind, err)
		}
	}
	conn, err := net.ListenUDP("udp4", local)
	if err != nil {
		return res, fmt.Errorf("netfuzz: bind %v: %w", local, err)
	}
	defer conn.Close()
	opts.logf("sending from %s to %s", conn.LocalAddr(), target)

	// Receiver: count and log anything the host sends back to our source port.
	var received, bytesRecv int64
	var firstOnce sync.Once
	var first []byte
	recvCtx, recvCancel := context.WithCancel(ctx)
	defer recvCancel()
	var recvWG sync.WaitGroup
	recvWG.Add(1)
	go func() {
		defer recvWG.Done()
		buf := make([]byte, 2048)
		for {
			if recvCtx.Err() != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				if recvCtx.Err() != nil {
					return
				}
				continue // timeout or transient WSAECONNRESET
			}
			atomic.AddInt64(&received, 1)
			atomic.AddInt64(&bytesRecv, int64(n))
			firstOnce.Do(func() {
				first = append([]byte(nil), buf[:min(n, 64)]...)
				opts.logf("host responded: %d bytes from %s", n, from)
			})
		}
	}()

	send := func(d []byte) {
		if _, err := conn.WriteToUDP(d, target); err != nil {
			res.SendErrors++
			if res.SendErrors <= 5 {
				opts.logf("send error (#%d): %v", res.SendErrors, err)
			}
			return
		}
		res.Sent++
		res.BytesSent += int64(len(d))
	}

	// liveness sends a valid CONNECT and watches the shared receive counter for
	// any reply within wait. It reuses the single receiver goroutine rather than
	// reading the socket itself, so it never races that goroutine for the reply.
	liveness := func() bool {
		before := atomic.LoadInt64(&received)
		if _, err := conn.WriteToUDP(validConnect(), target); err != nil {
			return false
		}
		deadline := time.Now().Add(opts.ProbeWait)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return false
			}
			if atomic.LoadInt64(&received) > before {
				return true
			}
			time.Sleep(20 * time.Millisecond)
		}
		return false
	}

	// Pre-run liveness probe.
	if opts.Probe {
		res.RespondedBefore = liveness()
		opts.logf("liveness before run: responded=%v", res.RespondedBefore)
	}

	// Prime a pending connection so per-connection handlers are reachable.
	if opts.Prime {
		send(validConnect())
		time.Sleep(50 * time.Millisecond)
	}

	// Drive the corpus.
	for iter := 0; iter < opts.Iterations; iter++ {
		if ctx.Err() != nil {
			break
		}
		res.Iterations = iter + 1
		for _, p := range corpus {
			if ctx.Err() != nil {
				break
			}
			send(p.Data)
			if opts.Delay > 0 {
				select {
				case <-ctx.Done():
				case <-time.After(opts.Delay):
				}
			}
		}
		opts.logf("iteration %d/%d done: sent=%d errors=%d", iter+1, opts.Iterations, res.Sent, res.SendErrors)
	}

	// Post-run liveness probe.
	if opts.Probe {
		res.RespondedAfter = liveness()
		opts.logf("liveness after run: responded=%v", res.RespondedAfter)
	}

	// Let late replies arrive, then stop the receiver.
	time.Sleep(200 * time.Millisecond)
	recvCancel()
	_ = conn.SetReadDeadline(time.Now())
	recvWG.Wait()

	res.Received = atomic.LoadInt64(&received)
	res.BytesReceived = atomic.LoadInt64(&bytesRecv)
	res.FirstResponse = first
	return res, nil
}

// validConnect is a canonical, well-formed CONNECT: the packet a real peer
// sends to open a handshake. Used to prime a connection and as the liveness
// probe.
func validConnect() []byte {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	body := ConnectBody(ProtoUDP, time.Now().UnixMicro(), CompNone, nonce)
	return FrameHonest(Header{Type: PTConnect}, body)
}

// categoriesOf returns the distinct category names present in a corpus, in
// first-seen order.
func categoriesOf(corpus []CraftedPacket) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range corpus {
		if !seen[p.Category] {
			seen[p.Category] = true
			out = append(out, p.Category)
		}
	}
	return out
}
