package agent

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/fixer"
)

const (
	webID = "2d1f6c4a9e8b7d0c3f5a6b1e4d7c0a9f8e2b5d6c1a4f7e0b3d9c2a5f8e1b4d7c"
	dbID  = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"
)

var t0 = time.Date(2026, 9, 23, 23, 0, 0, 0, time.UTC)

func execEvent(at time.Duration, uid uint32, containerID string) events.AuditEvent {
	ev := events.AuditEvent{
		Kind:    events.KindProcessExec,
		Time:    t0.Add(at),
		Node:    "worker-1",
		Process: events.Process{PID: 4242, UID: uid, Comm: "sh"},
		Data:    &events.ProcessExec{Filename: "/bin/sh"},
	}
	if containerID != "" {
		ev.Container = &events.Container{ID: containerID, Runtime: "containerd"}
	}
	return ev
}

func escalationEvent(at time.Duration, containerID string) events.AuditEvent {
	ev := execEvent(at, 0, containerID)
	ev.Kind = events.KindPrivilegeEscalation
	ev.Data = &events.PrivilegeEscalation{Syscall: "setuid", OldUID: 1000, NewUID: 0}
	return ev
}

func mustIngest(t *testing.T, a *Agent, evs ...events.AuditEvent) []string {
	t.Helper()
	ids, err := a.Ingest(evs)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	return ids
}

func TestIngestClassifiesAndAggregates(t *testing.T) {
	a := New(Config{})
	ids := mustIngest(t, a,
		execEvent(2*time.Second, 0, webID), // AEG-001
		execEvent(1*time.Second, 0, webID), // AEG-001 again, observed earlier
		escalationEvent(3*time.Second, webID),
		execEvent(0, 0, ""),      // host process: no rule applies
		execEvent(0, 1000, dbID), // non-root: no rule applies
	)

	idRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	wantSeverity := []events.Severity{
		events.SeverityMedium, events.SeverityMedium, events.SeverityCritical, events.SeverityInfo, events.SeverityInfo,
	}
	for i, id := range ids {
		if !idRe.MatchString(id) {
			t.Errorf("event ID %q is not a UUIDv7", id)
		}
		ev, err := a.Event(id)
		if err != nil {
			t.Fatalf("Event(%q): %v", id, err)
		}
		if ev.Severity != wantSeverity[i] {
			t.Errorf("event %d has severity %s, want %s", i, ev.Severity, wantSeverity[i])
		}
	}

	rems := a.Remediations(RemediationFilter{})
	if len(rems) != 2 {
		t.Fatalf("got %d remediations, want 2: %+v", len(rems), rems)
	}
	escalation, root := rems[0], rems[1] // most recently seen first
	if escalation.Rule.ID != "AEG-002" || root.Rule.ID != "AEG-001" {
		t.Fatalf("remediations are for rules %s and %s, want AEG-002 and AEG-001", escalation.Rule.ID, root.Rule.ID)
	}
	if root.Occurrences != 2 || root.EventID != ids[0] ||
		!root.FirstSeen.Equal(t0.Add(time.Second)) || !root.LastSeen.Equal(t0.Add(2*time.Second)) {
		t.Errorf("AEG-001 remediation = %+v, want 2 occurrences opened by %s, seen from +1s to +2s", root, ids[0])
	}
	wantOps := []fixer.Operation{
		{Op: fixer.OpSet, Path: "containers[*].securityContext.allowPrivilegeEscalation", Value: false},
		{Op: fixer.OpAdd, Path: "containers[*].securityContext.capabilities.drop", Value: "ALL"},
	}
	if !reflect.DeepEqual(escalation.Operations, wantOps) {
		t.Errorf("AEG-002 operations = %+v, want %+v", escalation.Operations, wantOps)
	}
}

func TestIngestIsAtomic(t *testing.T) {
	a := New(Config{})
	bad := execEvent(0, 0, webID)
	bad.Node = ""
	bad.Process.PID = 0
	_, err := a.Ingest([]events.AuditEvent{execEvent(0, 0, webID), bad})

	var inv *InvalidEventError
	if !errors.As(err, &inv) || inv.Index != 1 {
		t.Fatalf("Ingest error = %v, want an *InvalidEventError for event 1", err)
	}
	if got := fieldErrors(err); len(got) != 2 || got[0].Index != 1 || !strings.Contains(got[0].Message, "node") {
		t.Errorf("fieldErrors = %+v, want the node and pid violations of event 1", got)
	}
	if n := len(a.Events(EventFilter{})); n != 0 {
		t.Errorf("a rejected batch stored %d events", n)
	}
	if n := len(a.Remediations(RemediationFilter{})); n != 0 {
		t.Errorf("a rejected batch opened %d remediations", n)
	}
}

func TestEventsEvictsOldest(t *testing.T) {
	a := New(Config{MaxEvents: 2})
	ids := mustIngest(t, a, execEvent(0, 1000, ""), execEvent(1, 1000, ""), execEvent(2, 1000, ""))
	var got []string
	for _, ev := range a.Events(EventFilter{}) {
		got = append(got, ev.ID)
	}
	if want := []string{ids[2], ids[1]}; !reflect.DeepEqual(got, want) {
		t.Errorf("Events() = %v, want the two newest %v", got, want)
	}
	if _, err := a.Event(ids[0]); !errors.Is(err, ErrNotFound) {
		t.Errorf("Event(evicted) error = %v, want ErrNotFound", err)
	}
}

func TestEventsFilter(t *testing.T) {
	a := New(Config{})
	mustIngest(t, a,
		execEvent(0, 0, webID),    // medium
		escalationEvent(1, webID), // critical
		execEvent(2, 0, dbID),     // medium
		execEvent(3, 1000, ""),    // info
	)
	count := func(f EventFilter) int { return len(a.Events(f)) }
	for _, tt := range []struct {
		f    EventFilter
		want int
	}{
		{EventFilter{}, 4},
		{EventFilter{Kind: events.KindPrivilegeEscalation}, 1},
		{EventFilter{MinSeverity: events.SeverityMedium}, 3},
		{EventFilter{MinSeverity: events.SeverityCritical}, 1},
		{EventFilter{ContainerID: webID}, 2},
		{EventFilter{ContainerID: webID, Kind: events.KindProcessExec}, 1},
		{EventFilter{Limit: 3}, 3},
	} {
		if got := count(tt.f); got != tt.want {
			t.Errorf("Events(%+v) returned %d events, want %d", tt.f, got, tt.want)
		}
	}
}

func TestRemediationsEvictLeastRecentlySeen(t *testing.T) {
	a := New(Config{MaxRemediations: 1})
	mustIngest(t, a, execEvent(0, 0, webID), execEvent(time.Second, 0, dbID))
	rems := a.Remediations(RemediationFilter{})
	if len(rems) != 1 || rems[0].Container.ID != dbID {
		t.Fatalf("Remediations() = %+v, want only the one of the most recent container", rems)
	}
	// The evicted remediation opens again on its next occurrence.
	mustIngest(t, a, execEvent(2*time.Second, 0, webID))
	if rems := a.Remediations(RemediationFilter{ContainerID: webID}); len(rems) != 1 || rems[0].Occurrences != 1 {
		t.Errorf("Remediations(web) = %+v, want one new remediation", rems)
	}
}

func TestPatch(t *testing.T) {
	a := New(Config{})
	mustIngest(t, a, escalationEvent(0, webID))
	rem := a.Remediations(RemediationFilter{})[0]
	res, err := a.Patch(rem.ID, []byte("kind: Pod\nspec:\n  containers:\n  - name: web\n"))
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	const want = "kind: Pod\nspec:\n  containers:\n  - name: web\n    securityContext:\n" +
		"      allowPrivilegeEscalation: false\n      capabilities:\n        drop:\n        - ALL\n"
	if string(res.Manifest) != want {
		t.Errorf("patched manifest:\n%s\nwant:\n%s", res.Manifest, want)
	}
	if _, err := a.Patch("00000000-0000-7000-8000-000000000000", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("Patch(unknown) error = %v, want ErrNotFound", err)
	}
}
