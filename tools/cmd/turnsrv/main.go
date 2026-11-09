// Command turnsrv runs tools/turnsrv on its own, for tests of ICE agents
// outside mpemu and fafclient: it prints the URLs and one set of REST
// credentials, then serves until interrupted.
//
//	turnsrv [-ip 192.168.1.2] [-port 3478] [-for 60s]
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"faf-main/tools/journal"
	"faf-main/tools/turnsrv"
)

func main() {
	ip := flag.String("ip", "", "address to bind and relay from (default: the address of the outbound route)")
	port := flag.Int("port", 3478, "STUN/TURN port")
	dur := flag.Duration("for", 0, "stop after this long (0: until interrupted)")
	flag.Parse()
	if *ip == "" {
		*ip = "127.0.0.1"
		if c, err := net.Dial("udp4", "8.8.8.8:53"); err == nil {
			*ip = c.LocalAddr().(*net.UDPAddr).IP.String()
			c.Close()
		}
	}
	j, _ := journal.New("", func(r journal.Record) { fmt.Println(r.Kind, r.Text) })
	ts, err := turnsrv.Start(turnsrv.Config{ListenIP: *ip, Port: *port, PublicHost: *ip, PublicIP: *ip}, j)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer ts.Close()
	user, pass := ts.Credentials(1, 1, 24*time.Hour)
	fmt.Printf("urls %v\nuser %s\npassword %s\n", ts.URLs(), user, pass)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *dur)
		defer cancel()
	}
	<-ctx.Done()
}
