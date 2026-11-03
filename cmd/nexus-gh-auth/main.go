// Command nexus-gh-auth is a GitHub login proxy for Nexus Repository
// Community Edition. See SPEC.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smeup-ergon/nexus-gh-auth/internal/bridge"
	"github.com/smeup-ergon/nexus-gh-auth/internal/config"
	"github.com/smeup-ergon/nexus-gh-auth/internal/github"
	"github.com/smeup-ergon/nexus-gh-auth/internal/nexus"
)

const shutdownTimeout = 30 * time.Second

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))

	gh := github.New(cfg.GitHubURL, cfg.GitHubAPIURL, cfg.GitHubClientID, cfg.GitHubClientSecret, cfg.GitHubOrgs)
	nx := nexus.New(cfg.NexusURL, cfg.NexusAdminUser, cfg.NexusAdminPassword)
	b := bridge.New(cfg, gh, nx, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	servers := []*http.Server{newServer(cfg.WebListen, b.WebHandler())}
	if cfg.DockerListen != "" {
		servers = append(servers, newServer(cfg.DockerListen, b.DockerHandler()))
	}
	errc := make(chan error, len(servers)+1)
	for _, s := range servers {
		log.Info("listening", "addr", s.Addr)
		go func() {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("listener %s: %w", s.Addr, err)
			}
		}()
	}
	go func() {
		if err := b.Startup(ctx); err != nil && ctx.Err() == nil {
			errc <- err
		}
	}()

	select {
	case err = <-errc:
	case <-ctx.Done():
		log.Info("shutting down")
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, s := range servers {
		if serr := s.Shutdown(sctx); serr != nil {
			log.Warn("shutdown", "addr", s.Addr, "err", serr)
		}
	}
	return err
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No read/write timeouts: large artifact and image transfers can
		// take a long time.
	}
}

// healthcheck lets the distroless image use a Docker HEALTHCHECK without a
// shell or curl.
func healthcheck() int {
	addr := os.Getenv("WEB_LISTEN")
	if addr == "" {
		addr = ":8081"
	}
	if addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + addr + "/_bridge/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
