// Command netfuzz plays a hostile UDP peer against a Forged Alliance (Moho
// engine) lobby host: it crafts datagrams the way the engine's own transport
// frames them and then breaks every field the receive path validates, so a run
// drives the host's parser through each reject branch and handler state
// transition. It is a robustness probe -- it only sends UDP to the address you
// name -- used to show at runtime that crafted packets no longer crash the host.
//
// Usage:
//
//	netfuzz -target 127.0.0.1:17890 [flags]
//
// The crafted-packet families are derived field-by-field from the C++ source
// (src/moho/net/SNetPacket.*, NetTransportEnums.h, CNetUDPConnector.cpp,
// CNetUDPConnection.cpp). List them with -list.
//
// Typical run against a host sitting in a lobby, binding the advertised source
// address an isolated host requires:
//
//	netfuzz -target 192.168.42.77:17890 -bind 192.168.42.77:0 -probe
//
// Exit status: 0 when the corpus was sent. With -probe, a nonzero status when
// the host answered the pre-run probe but not the post-run one (-fail-on-death),
// i.e. the fuzzing likely took the host down.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"faf-main/tools/netfuzz"
)

func main() {
	var (
		target      = flag.String("target", "", "host lobby UDP endpoint host:port (required)")
		bind        = flag.String("bind", "", "local UDP source address host:port (empty: OS picks; use advertised IP with :0 on an isolated host)")
		seed        = flag.Int64("seed", 0, "RNG seed for a reproducible corpus (0: time-based, printed)")
		iterations  = flag.Int("iterations", 1, "replay the whole corpus this many times")
		randomN     = flag.Int("random", 256, "number of fully random datagrams in the 'random' category")
		cats        = flag.String("categories", "", "comma-separated attack families (empty: all; see -list)")
		delay       = flag.Duration("delay", 0, "delay between datagrams, e.g. 1ms")
		prime       = flag.Bool("prime", true, "send a valid CONNECT first so per-connection handlers are reachable")
		probe       = flag.Bool("probe", false, "liveness CONNECT + wait for a reply, before and after the run")
		probeWait   = flag.Duration("probe-wait", 2*time.Second, "how long each liveness probe waits for a reply")
		failOnDeath = flag.Bool("fail-on-death", true, "with -probe, exit nonzero if the host answered before but not after")
		dryRun      = flag.Bool("dry-run", false, "generate and print the corpus without sending")
		list        = flag.Bool("list", false, "list attack families and exit")
		quiet       = flag.Bool("quiet", false, "only print the final summary")
	)
	flag.Parse()

	if *list {
		desc := netfuzz.Describe()
		fmt.Println("netfuzz attack families:")
		for _, name := range netfuzz.Categories() {
			fmt.Printf("  %-11s %s\n", name, desc[name])
		}
		return
	}

	if *seed == 0 {
		*seed = time.Now().UnixNano()
	}

	logger := log.New(os.Stderr, "netfuzz ", log.Ltime|log.Lmicroseconds)
	if *quiet {
		logger = nil
	}

	var categories []string
	if s := strings.TrimSpace(*cats); s != "" {
		for _, c := range strings.Split(s, ",") {
			if c = strings.TrimSpace(c); c != "" {
				categories = append(categories, c)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := netfuzz.Options{
		Target:     *target,
		Bind:       *bind,
		Prime:      *prime,
		Delay:      *delay,
		Iterations: *iterations,
		Probe:      *probe,
		ProbeWait:  *probeWait,
		DryRun:     *dryRun,
		Gen: netfuzz.GenOptions{
			Seed:        *seed,
			RandomCount: *randomN,
			Categories:  categories,
		},
		Logger: logger,
	}

	res, err := netfuzz.Run(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	fmt.Printf("seed=%d corpus=%d iterations=%d sent=%d send_errors=%d bytes_sent=%d received=%d bytes_received=%d\n",
		*seed, res.Corpus, res.Iterations, res.Sent, res.SendErrors, res.BytesSent, res.Received, res.BytesReceived)
	if *probe {
		fmt.Printf("liveness: responded_before=%v responded_after=%v\n", res.RespondedBefore, res.RespondedAfter)
	}
	if len(res.FirstResponse) > 0 {
		fmt.Printf("first_response=% x\n", res.FirstResponse)
	}

	if *dryRun {
		return
	}

	// A crashed host shows up as sends starting to fail (WSAECONNRESET) or as a
	// liveness probe that answered before the run and went silent after it.
	if *probe && *failOnDeath && res.RespondedBefore && !res.RespondedAfter {
		fmt.Fprintln(os.Stderr, "FAIL: host answered before the run but not after -- it may have crashed")
		os.Exit(1)
	}
}
