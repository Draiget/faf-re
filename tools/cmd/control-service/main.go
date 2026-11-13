// Command control-service is the web side of the dedicated servers: FAF sign-in (OpenID Connect, authorization code
// with PKCE), roles (admin, organiser, player) and tournament allowlists from its configuration, the server hosts
// (tools/cmd/server-host) it follows, organised lobbies made on the host chosen or the least loaded one, players'
// requests for games they host, and the live state of every host and lobby, cached in Redis (or in memory) and
// pushed to web clients as Server-Sent Events.
//
// It is never in the game's path: players' games connect to the lobby servers, and the service only talks to the
// hosts' REST APIs.
//
//	control-service --config control.yaml [--redis 127.0.0.1:6379 --redis-password-file redis.pass]
//
// docs/CONTROL_SERVICE.md describes the configuration and the API.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", "control.yaml", "the configuration file (YAML)")
	listen := flag.String("listen", "", "address to serve on (default: the configuration's listen, else 127.0.0.1:27190)")
	redisAddr := flag.String("redis", "", "Redis address (host:port); without it the cache is in memory")
	redisPassFile := flag.String("redis-password-file", "", "file with the Redis password")
	redisDB := flag.Int("redis-db", 0, "Redis database number")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var store Store = newMemStore()
	if *redisAddr != "" {
		pass := ""
		if *redisPassFile != "" {
			if pass, err = readSecret(*redisPassFile, 1); err != nil {
				log.Fatalf("redis password: %v", err)
			}
		}
		rs, err := newRedisStore(ctx, *redisAddr, pass, *redisDB, cfg.KeyPrefix)
		if err != nil {
			log.Fatalf("redis at %s: %v (leave --redis out to cache in memory)", *redisAddr, err)
		}
		store = rs
	}
	defer store.Close()

	s := newServer(ctx, cfg, *cfgPath, store)
	srv := &http.Server{Addr: cfg.Listen, Handler: s, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10,
		IdleTimeout: 2 * time.Minute}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for v := range sig {
			if v == syscall.SIGHUP {
				if err := s.reload(); err != nil {
					log.Printf("configuration not reloaded: %v", err)
				}
				continue
			}
			log.Printf("stopping")
			s.reg.stop()
			cancel()
			sctx, done := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(sctx)
			done()
			return
		}
	}()
	names := []string{}
	for _, h := range cfg.Hosts {
		names = append(names, h.Name)
	}
	log.Printf("control-service on http://%s (public %s): sign-in at %s, cache %s, hosts %s", cfg.Listen, cfg.PublicURL,
		cfg.OIDC.Issuer, store.Kind(), strings.Join(names, ", "))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
