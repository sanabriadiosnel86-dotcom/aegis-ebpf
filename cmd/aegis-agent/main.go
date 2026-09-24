// Command aegis-agent is the control plane of Aegis-eBPF. It receives the
// events of the eBPF probe, evaluates them against the rules of the syntactic
// fixer and serves the API specified in api/openapi.yaml.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/agent"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "aegis-agent:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("aegis-agent", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "`address` to serve the HTTP API on")
	maxEvents := fs.Int("max-events", 10000, "number of recent events kept in memory")
	maxRemediations := fs.Int("max-remediations", 10000, "number of remediations kept in memory")
	logLevel := fs.String("log-level", "info", "log `level`: debug, info, warn or error")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("aegis-agent", version)
		return nil
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("-log-level: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ag := agent.New(agent.Config{MaxEvents: *maxEvents, MaxRemediations: *maxRemediations, Logger: log})
	srv := &http.Server{
		Handler:           ag.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Info("aegis-agent started", "version", version, "listen", ln.Addr().String())

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
