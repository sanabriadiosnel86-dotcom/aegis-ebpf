// Command aegis-agent is the control plane of Aegis-eBPF. It receives the
// audit events of the eBPF probe, evaluates them against the rules of the
// syntactic fixer, resolves the Kubernetes pod of each container, and serves
// the API specified in api/openapi.yaml plus a live event stream.
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
	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/decoy"
	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/k8s"
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
	enrichK8s := fs.Bool("enrich-k8s", false, "resolve pod names from the Kubernetes API (in-cluster)")
	nodeName := fs.String("node-name", os.Getenv("NODE_NAME"), "only resolve pods on this `node` (defaults to $NODE_NAME)")
	webDir := fs.String("web-dir", "", "serve the dashboard from this `directory` at the web root")
	deployDecoy := fs.Bool("decoy", false, "deploy a honeypot decoy on high-severity events (needs the Docker socket)")
	decoyImage := fs.String("decoy-image", decoy.DefaultImage, "container `image` used for the decoy")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := agent.Config{
		MaxEvents:       *maxEvents,
		MaxRemediations: *maxRemediations,
		Logger:          log,
		WebDir:          *webDir,
	}
	if *enrichK8s {
		enricher, err := startEnricher(ctx, *nodeName, log)
		if err != nil {
			return err
		}
		cfg.Enricher = enricher
	}
	if *deployDecoy {
		responder, err := decoy.NewResponder(decoy.Config{Image: *decoyImage, Logger: log})
		if err != nil {
			return fmt.Errorf("starting the decoy responder: %w", err)
		}
		defer responder.Close()
		cfg.Responder = responder
		log.Warn("decoy responder enabled: high-severity events will start honeypot containers")
	}

	ag := agent.New(cfg)
	srv := &http.Server{
		Handler:           ag.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// No write timeout: the /v1/stream WebSocket is long-lived, and each
		// request handler bounds its own writes.
		WriteTimeout: 0,
		IdleTimeout:  2 * time.Minute,
		ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}

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

// startEnricher builds the Kubernetes pod cache and starts its background
// refresh, returning an agent.Enricher backed by it.
func startEnricher(ctx context.Context, nodeName string, log *slog.Logger) (agent.Enricher, error) {
	client, err := k8s.InCluster()
	if err != nil {
		return nil, fmt.Errorf("connecting to the Kubernetes API: %w", err)
	}
	cache := k8s.NewPodCache(client, nodeName, log)
	// Prime the cache so early events are enriched; failure is not fatal, the
	// background loop will retry.
	if err := cache.Refresh(ctx); err != nil {
		log.Warn("priming the pod cache failed", "error", err)
	}
	go cache.Run(ctx, 30*time.Second)
	return podEnricher{cache}, nil
}

// podEnricher adapts a k8s.PodCache to the agent.Enricher interface.
type podEnricher struct{ cache *k8s.PodCache }

func (e podEnricher) Lookup(containerID string) (agent.PodInfo, bool) {
	pod, ok := e.cache.Lookup(containerID)
	if !ok {
		return agent.PodInfo{}, false
	}
	return agent.PodInfo{Name: pod.Name, Namespace: pod.Namespace, UID: pod.UID}, true
}
