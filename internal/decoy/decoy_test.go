package decoy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
)

const (
	webID = "2d1f6c4a9e8b7d0c3f5a6b1e4d7c0a9f8e2b5d6c1a4f7e0b3d9c2a5f8e1b4d7c"
	dbID  = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"
)

// fakeDeployer records deployments and can be made to fail.
type fakeDeployer struct {
	mu       sync.Mutex
	deployed []Trigger
	removed  []Decoy
	err      error
}

func (f *fakeDeployer) Deploy(_ context.Context, t Trigger) (Decoy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Decoy{}, f.err
	}
	f.deployed = append(f.deployed, t)
	return Decoy{ID: "id-" + t.ContainerID, Name: decoyName(t.ContainerID), Network: "shopnet"}, nil
}

func (f *fakeDeployer) Remove(_ context.Context, d Decoy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, d)
	return nil
}

func (f *fakeDeployer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.deployed)
}

func critical(containerID string) events.AuditEvent {
	ev := events.AuditEvent{Kind: events.KindPrivilegeEscalation, Severity: events.SeverityCritical}
	if containerID != "" {
		ev.Container = &events.Container{ID: containerID}
	}
	return ev
}

func TestRespondDeploysOncePerContainer(t *testing.T) {
	f := &fakeDeployer{}
	r := newResponder(Config{deployer: f, MinInterval: time.Nanosecond})

	r.Respond(critical(webID))
	r.Respond(critical(webID)) // same container: deduplicated
	if f.count() != 1 {
		t.Fatalf("deployed %d decoys, want 1 for the repeated container", f.count())
	}
	time.Sleep(time.Millisecond) // clear the rate limit
	r.Respond(critical(dbID))
	if f.count() != 2 {
		t.Errorf("deployed %d decoys, want one per distinct container", f.count())
	}
	if d := r.Deployed(); len(d) != 2 {
		t.Errorf("tracked %d decoys, want 2", len(d))
	}
}

func TestRespondIgnoresHostEvents(t *testing.T) {
	f := &fakeDeployer{}
	r := newResponder(Config{deployer: f})
	r.Respond(critical("")) // no container
	if f.count() != 0 {
		t.Errorf("deployed a decoy for a host event")
	}
}

func TestRespondRateLimits(t *testing.T) {
	f := &fakeDeployer{}
	r := newResponder(Config{deployer: f, MinInterval: time.Hour})
	r.Respond(critical(webID))
	r.Respond(critical(dbID)) // within the interval: dropped
	if f.count() != 1 {
		t.Errorf("deployed %d decoys, want the rate limit to allow only 1", f.count())
	}
}

func TestRespondHonorsCap(t *testing.T) {
	f := &fakeDeployer{}
	r := newResponder(Config{deployer: f, MaxDecoys: 1, MinInterval: time.Nanosecond})
	r.Respond(critical(webID))
	time.Sleep(time.Millisecond)
	r.Respond(critical(dbID)) // over the cap
	if f.count() != 1 {
		t.Errorf("deployed %d decoys, want the cap to allow only 1", f.count())
	}
}

func TestRespondReleasesSlotOnFailure(t *testing.T) {
	f := &fakeDeployer{err: errors.New("docker down")}
	r := newResponder(Config{deployer: f, MinInterval: time.Nanosecond})
	r.Respond(critical(webID)) // fails; the slot must be freed
	if len(r.Deployed()) != 0 {
		t.Errorf("a failed deployment left a decoy tracked: %v", r.Deployed())
	}
	f.err = nil
	time.Sleep(time.Millisecond)
	r.Respond(critical(webID)) // must be allowed to retry the same container
	if f.count() != 1 {
		t.Errorf("the same container could not be retried after a failure")
	}
}

func TestCloseRemovesDecoys(t *testing.T) {
	f := &fakeDeployer{}
	r := newResponder(Config{deployer: f, MinInterval: time.Nanosecond})
	r.Respond(critical(webID))
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.removed) != 1 || f.removed[0].ID != "id-"+webID {
		t.Errorf("Close removed %v, want the one decoy", f.removed)
	}
}

func TestPickNetworkPrefersUserDefined(t *testing.T) {
	info := &containerInfo{}
	info.NetworkSettings.Networks = map[string]struct {
		NetworkID string `json:"NetworkID"`
	}{"bridge": {}, "shopnet": {}}
	if got := pickNetwork(info); got != "shopnet" {
		t.Errorf("pickNetwork = %q, want the user-defined network", got)
	}

	onlyHost := &containerInfo{}
	onlyHost.NetworkSettings.Networks = map[string]struct {
		NetworkID string `json:"NetworkID"`
	}{"host": {}, "none": {}}
	if got := pickNetwork(onlyHost); got != "" {
		t.Errorf("pickNetwork = %q, want no placeable network", got)
	}
}

func TestSplitImage(t *testing.T) {
	tests := map[string][2]string{
		"alpine:3.20":                 {"alpine", "3.20"},
		"alpine":                      {"alpine", "latest"},
		"ghcr.io/acme/app:1.2":        {"ghcr.io/acme/app", "1.2"},
		"registry:5000/app":           {"registry:5000/app", "latest"},
		"alpine@sha256:" + hex64ish(): {"alpine@sha256:" + hex64ish(), "latest"},
	}
	for in, want := range tests {
		name, tag := splitImage(in)
		if name != want[0] || tag != want[1] {
			t.Errorf("splitImage(%q) = %q, %q, want %q, %q", in, name, tag, want[0], want[1])
		}
	}
}

func hex64ish() string { return "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd" }
