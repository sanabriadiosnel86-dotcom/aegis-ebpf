// Package decoy is the adaptive-deception responder of Aegis-eBPF. When the
// agent raises a high-severity audit event, the responder starts a lightweight
// honeypot ("decoy") container on the same network as the offending workload,
// to catch and record lateral-movement probes.
//
// The decoy is deliberately inert: it presents a fake service banner, logs the
// source of every connection, and never runs anything a client sends. This is
// the only component of Aegis-eBPF that changes state on the host, and it is
// opt-in (the agent's --decoy flag); everything else stays passive.
package decoy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
)

// DefaultImage is the base image of the decoy: small and ubiquitous.
const DefaultImage = "alpine:3.20"

// DefaultSocket is the usual path of the Docker Engine socket.
const DefaultSocket = "/var/run/docker.sock"

// decoyPort is the port the decoy listens on, presenting a fake SSH banner.
const decoyPort = 2222

// Label marks the containers the responder creates, so they can be told apart
// from real workloads and cleaned up.
const Label = "aegis.decoy"

// Config configures a Responder.
type Config struct {
	// Image is the decoy's base image. Defaults to DefaultImage.
	Image string
	// Socket is the Docker socket path. Defaults to DefaultSocket.
	Socket string
	// MaxDecoys caps how many decoys run at once. Defaults to 16.
	MaxDecoys int
	// MinInterval is the shortest time between two deployments, a rate limit
	// against event storms. Defaults to 5s.
	MinInterval time.Duration
	// RemoveOnClose removes the decoys the responder created when it closes.
	// Defaults to true.
	RemoveOnClose *bool
	Logger        *slog.Logger
	// deployer overrides the Docker-backed deployer in tests.
	deployer Deployer
}

// Trigger describes the event that prompted a decoy.
type Trigger struct {
	ContainerID string
	Severity    events.Severity
	Rule        string
}

// Decoy identifies a deployed honeypot container.
type Decoy struct {
	ID      string
	Name    string
	Network string
}

// Deployer starts a decoy for a trigger. The Docker implementation inspects
// the offending container to find its network; tests supply a fake.
type Deployer interface {
	Deploy(ctx context.Context, t Trigger) (Decoy, error)
	Remove(ctx context.Context, d Decoy) error
}

// Responder implements agent.Responder: it decides when to deploy a decoy and
// enforces the deduplication, rate limit and cap that keep the reaction
// proportionate.
type Responder struct {
	deployer      Deployer
	log           *slog.Logger
	maxDecoys     int
	minInterval   time.Duration
	removeOnClose bool

	mu          sync.Mutex
	byContainer map[string]Decoy // offending container ID -> its decoy
	lastDeploy  time.Time
}

// NewResponder builds a Responder backed by the Docker socket. It fails when
// the socket is not reachable, so that --decoy reports the problem at startup.
func NewResponder(cfg Config) (*Responder, error) {
	if cfg.deployer == nil {
		socket := cfg.Socket
		if socket == "" {
			socket = DefaultSocket
		}
		image := cfg.Image
		if image == "" {
			image = DefaultImage
		}
		client, err := newDockerClient(socket)
		if err != nil {
			return nil, err
		}
		cfg.deployer = &dockerDeployer{client: client, image: image}
	}
	return newResponder(cfg), nil
}

func newResponder(cfg Config) *Responder {
	if cfg.MaxDecoys <= 0 {
		cfg.MaxDecoys = 16
	}
	if cfg.MinInterval <= 0 {
		cfg.MinInterval = 5 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	remove := cfg.RemoveOnClose == nil || *cfg.RemoveOnClose
	return &Responder{
		deployer:      cfg.deployer,
		log:           cfg.Logger,
		maxDecoys:     cfg.MaxDecoys,
		minInterval:   cfg.MinInterval,
		removeOnClose: remove,
		byContainer:   make(map[string]Decoy),
	}
}

// Respond deploys a decoy for a high-severity event, subject to the policy.
// The agent calls it in its own goroutine, so it may block on Docker.
func (r *Responder) Respond(ev events.AuditEvent) {
	if ev.Container == nil || ev.Container.ID == "" {
		return // no network to place a decoy on
	}
	trigger := Trigger{ContainerID: ev.Container.ID, Severity: ev.Severity}
	if !r.admit(trigger) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	decoy, err := r.deployer.Deploy(ctx, trigger)
	if err != nil {
		r.release(trigger.ContainerID)
		r.log.Error("deploying a decoy failed", "container", trigger.ContainerID, "error", err)
		return
	}
	r.confirm(trigger.ContainerID, decoy)
	r.log.Warn("decoy deployed",
		"decoy", decoy.Name, "network", decoy.Network,
		"offending_container", trigger.ContainerID, "severity", ev.Severity)
}

// admit applies the policy and, if the trigger passes, reserves a slot for it
// so concurrent responders do not double-deploy.
func (r *Responder) admit(t Trigger) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byContainer[t.ContainerID]; exists {
		return false // one decoy per offending container
	}
	if len(r.byContainer) >= r.maxDecoys {
		r.log.Warn("decoy cap reached; not deploying", "cap", r.maxDecoys, "container", t.ContainerID)
		return false
	}
	if !r.lastDeploy.IsZero() && time.Since(r.lastDeploy) < r.minInterval {
		return false // rate limit
	}
	r.lastDeploy = time.Now()
	r.byContainer[t.ContainerID] = Decoy{} // reserve; filled in by confirm
	return true
}

func (r *Responder) confirm(containerID string, d Decoy) {
	r.mu.Lock()
	r.byContainer[containerID] = d
	r.mu.Unlock()
}

func (r *Responder) release(containerID string) {
	r.mu.Lock()
	delete(r.byContainer, containerID)
	r.mu.Unlock()
}

// Deployed returns a snapshot of the decoys currently tracked.
func (r *Responder) Deployed() []Decoy {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Decoy, 0, len(r.byContainer))
	for _, d := range r.byContainer {
		if d.ID != "" {
			out = append(out, d)
		}
	}
	return out
}

// Close removes the decoys the responder created, when configured to.
func (r *Responder) Close() error {
	if !r.removeOnClose {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var errs []error
	for _, d := range r.Deployed() {
		if err := r.deployer.Remove(ctx, d); err != nil {
			errs = append(errs, err)
		} else {
			r.log.Info("decoy removed", "decoy", d.Name)
		}
	}
	return errors.Join(errs...)
}

// dockerDeployer deploys decoys as Docker containers.
type dockerDeployer struct {
	client *dockerClient
	image  string
}

func (d *dockerDeployer) Deploy(ctx context.Context, t Trigger) (Decoy, error) {
	info, err := d.client.inspect(ctx, t.ContainerID)
	if err != nil {
		return Decoy{}, fmt.Errorf("inspecting the offending container: %w", err)
	}
	network := pickNetwork(info)
	if network == "" {
		return Decoy{}, fmt.Errorf("the offending container is on no reachable network")
	}
	name := decoyName(t.ContainerID)
	req := createRequest{
		Image:  d.image,
		Cmd:    []string{"sh", "-c", listenerScript},
		Labels: map[string]string{Label: "true", "aegis.offending-container": t.ContainerID},
		HostConfig: hostConfig{
			NetworkMode: network,
			Memory:      64 << 20, // 64 MiB
			PidsLimit:   64,
			CapDrop:     []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges"},
		},
	}
	id, err := d.client.create(ctx, name, req)
	if err != nil {
		return Decoy{}, fmt.Errorf("creating the decoy: %w", err)
	}
	if err := d.client.start(ctx, id); err != nil {
		_ = d.client.remove(ctx, id)
		return Decoy{}, fmt.Errorf("starting the decoy: %w", err)
	}
	return Decoy{ID: id, Name: name, Network: network}, nil
}

func (d *dockerDeployer) Remove(ctx context.Context, dec Decoy) error {
	return d.client.remove(ctx, dec.ID)
}

// listenerScript is the decoy's command: an inert honeypot. It presents a
// fake SSH banner, logs the source of every connection (nc -v), reads and
// discards whatever the client sends, and loops. It never runs client input.
var listenerScript = fmt.Sprintf(
	`echo "aegis decoy listening on :%d"; `+
		`while true; do `+
		`printf 'SSH-2.0-OpenSSH_9.6\r\n' | nc -l -p %d -w 10 -v 2>&1; `+
		`echo "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ) decoy session ended"; `+
		`done`,
	decoyPort, decoyPort)

// pickNetwork chooses the network to place the decoy on: the same network as
// the offending container, preferring a user-defined one over the default
// bridge so the decoy sits beside real workloads.
func pickNetwork(info *containerInfo) string {
	best := ""
	for name := range info.NetworkSettings.Networks {
		if name == "host" || name == "none" {
			continue
		}
		if best == "" || (best == "bridge" && name != "bridge") {
			best = name
		}
	}
	return best
}

func decoyName(containerID string) string {
	short := containerID
	if len(short) > 12 {
		short = short[:12]
	}
	return "aegis-decoy-" + strings.ToLower(short)
}
