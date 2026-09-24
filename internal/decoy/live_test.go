package decoy

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDeployerLive runs against the real Docker socket. It is skipped unless
// AEGIS_DOCKER_LIVE=1 and the socket is present.
func TestDeployerLive(t *testing.T) {
	if os.Getenv("AEGIS_DOCKER_LIVE") != "1" {
		t.Skip("set AEGIS_DOCKER_LIVE=1 to run the live Docker test")
	}
	run := func(args ...string) string {
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("network", "create", "aegis-live-net")
	defer exec.Command("docker", "network", "rm", "aegis-live-net").Run()
	target := run("run", "-d", "--rm", "--network", "aegis-live-net", "alpine:3.20", "sleep", "120")
	defer exec.Command("docker", "rm", "-f", target).Run()

	client, err := newDockerClient(DefaultSocket)
	if err != nil {
		t.Fatal(err)
	}
	dep := &dockerDeployer{client: client, image: DefaultImage}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	decoy, err := dep.Deploy(ctx, Trigger{ContainerID: target, Severity: "critical"})
	if err != nil {
		t.Fatal(err)
	}
	defer dep.Remove(context.Background(), decoy)

	if decoy.Network != "aegis-live-net" {
		t.Errorf("decoy on network %q, want aegis-live-net", decoy.Network)
	}
	// The decoy must be running and on the same network.
	net := run("inspect", "-f", "{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}", decoy.ID)
	state := run("inspect", "-f", "{{.State.Running}}", decoy.ID)
	label := run("inspect", "-f", "{{index .Config.Labels \"aegis.decoy\"}}", decoy.ID)
	t.Logf("decoy=%s network=%s running=%s label=%s", decoy.Name, net, state, label)
	if net != "aegis-live-net" || state != "true" || label != "true" {
		t.Errorf("decoy misplaced: network=%s running=%s label=%s", net, state, label)
	}
	time.Sleep(1500 * time.Millisecond)
	logs := run("logs", decoy.ID)
	if !strings.Contains(logs, "listening on :2222") {
		t.Errorf("decoy did not start its listener; logs:\n%s", logs)
	}
}
