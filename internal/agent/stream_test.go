package agent

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
)

// fakeEnricher resolves a fixed set of containers to pods.
type fakeEnricher map[string]PodInfo

func (f fakeEnricher) Lookup(containerID string) (PodInfo, bool) {
	pod, ok := f[containerID]
	return pod, ok
}

func TestIngestEnrichesPod(t *testing.T) {
	pod := PodInfo{Name: "web-7d9f", Namespace: "shop", UID: "6c3b1f0e-5d4a-4f2b-9e8d-7c6b5a4f3e2d"}
	a := New(Config{Enricher: fakeEnricher{webID: pod}})

	mustIngest(t, a, execEvent(0, 0, webID)) // has a container, no pod
	ev := a.Events(EventFilter{})[0]
	if ev.Container.Pod == nil || ev.Container.Pod.Name != "web-7d9f" || ev.Container.Pod.Namespace != "shop" {
		t.Fatalf("event pod = %+v, want the web pod", ev.Container.Pod)
	}

	// A host process (no container) is left alone.
	mustIngest(t, a, execEvent(0, 1000, ""))
	if host := a.Events(EventFilter{})[0]; host.Container != nil {
		t.Errorf("host event gained a container: %+v", host.Container)
	}

	// An unknown container is simply not enriched.
	mustIngest(t, a, execEvent(0, 0, dbID))
	if ev := a.Events(EventFilter{ContainerID: dbID})[0]; ev.Container.Pod != nil {
		t.Errorf("unknown container was enriched: %+v", ev.Container.Pod)
	}
}

func TestStreamBroadcastsEvents(t *testing.T) {
	a := New(Config{})
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()

	url := "ws" + srv.URL[len("http"):] + "/v1/stream"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dialing the stream: %v", err)
	}
	defer conn.CloseNow()

	// The subscriber must be registered before the event is published;
	// retry ingesting until the first event arrives.
	deadline := time.Now().Add(3 * time.Second)
	var got events.AuditEvent
	for {
		mustIngest(t, a, escalationEvent(0, webID))
		readCtx, c := context.WithTimeout(ctx, 200*time.Millisecond)
		err := wsjson.Read(readCtx, conn, &got)
		c()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no event received on the stream: %v", err)
		}
	}
	if got.Kind != events.KindPrivilegeEscalation || got.Severity != events.SeverityCritical {
		t.Errorf("streamed event = %+v, want a critical privilege_escalation", got)
	}
	if got.Container == nil || got.Container.ID != webID {
		t.Errorf("streamed event container = %+v, want %s", got.Container, webID)
	}
}

// countingResponder records the events it is asked to respond to.
type countingResponder struct {
	ch chan events.AuditEvent
}

func (c *countingResponder) Respond(ev events.AuditEvent) { c.ch <- ev }

func TestResponderSeesOnlyHighSeverity(t *testing.T) {
	resp := &countingResponder{ch: make(chan events.AuditEvent, 8)}
	a := New(Config{Responder: resp})

	// info (host exec), medium (container exec) and critical (escalation).
	mustIngest(t, a, execEvent(0, 1000, ""))
	mustIngest(t, a, execEvent(0, 0, webID))
	mustIngest(t, a, escalationEvent(0, webID))

	select {
	case ev := <-resp.ch:
		if ev.Severity.Rank() < events.SeverityHigh.Rank() {
			t.Errorf("responder saw a %s event, want only high or above", ev.Severity)
		}
		if ev.Kind != events.KindPrivilegeEscalation {
			t.Errorf("responder saw %s, want the escalation", ev.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("responder was not called for the critical event")
	}
	// Only the one critical event should have been dispatched.
	select {
	case ev := <-resp.ch:
		t.Errorf("responder called a second time, for %s", ev.Severity)
	case <-time.After(200 * time.Millisecond):
	}
}
