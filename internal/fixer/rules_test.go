package fixer

import (
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
)

const containerID = "2d1f6c4a9e8b7d0c3f5a6b1e4d7c0a9f8e2b5d6c1a4f7e0b3d9c2a5f8e1b4d7c"

func event(kind events.Kind, uid uint32, data events.Data, container *events.Container) *events.AuditEvent {
	return &events.AuditEvent{
		Kind:      kind,
		Time:      time.Unix(1790000000, 0),
		Node:      "worker-1",
		Process:   events.Process{PID: 42, UID: uid, Comm: "sh"},
		Container: container,
		Data:      data,
	}
}

func TestDefaultRulesMatch(t *testing.T) {
	c := &events.Container{ID: containerID}
	exec := &events.ProcessExec{Filename: "/bin/sh"}
	open := func(path string) events.Data {
		return &events.FileOpen{Path: path, Flags: []string{"O_WRONLY"}}
	}
	escalation := &events.PrivilegeEscalation{Syscall: "setuid", OldUID: 1000, NewUID: 0}

	tests := []struct {
		name string
		ev   *events.AuditEvent
		want []string // IDs of the matching rules
	}{
		{"root exec in container", event(events.KindProcessExec, 0, exec, c), []string{"AEG-001"}},
		{"non-root exec in container", event(events.KindProcessExec, 1000, exec, c), nil},
		{"root exec on the host", event(events.KindProcessExec, 0, exec, nil), nil},
		{"escalation in container", event(events.KindPrivilegeEscalation, 0, escalation, c), []string{"AEG-002"}},
		{"escalation on the host", event(events.KindPrivilegeEscalation, 0, escalation, nil), nil},
		{"write to /etc", event(events.KindFileOpen, 0, open("/etc/passwd"), c), []string{"AEG-003"}},
		{"write to /usr/bin", event(events.KindFileOpen, 0, open("/usr/local/bin/kubectl"), c), []string{"AEG-003"}},
		{"write through dot-dot", event(events.KindFileOpen, 0, open("/tmp/../etc/shadow"), c), []string{"AEG-003"}},
		{"write to /tmp", event(events.KindFileOpen, 0, open("/tmp/../tmp/x"), c), nil},
		{"write to a lookalike", event(events.KindFileOpen, 0, open("/etcetera/x"), c), nil},
		{"relative path", event(events.KindFileOpen, 0, open("etc/passwd"), c), nil},
		{"write to /etc on the host", event(events.KindFileOpen, 0, open("/etc/passwd"), nil), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, r := range DefaultRules() {
				if r.Matches(tt.ev) {
					got = append(got, r.ID)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("matching rules = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRulePlanTargetsContainer(t *testing.T) {
	r := DefaultRules()[0]
	named := event(events.KindProcessExec, 0, &events.ProcessExec{Filename: "/bin/sh"},
		&events.Container{ID: containerID, Name: "web"})
	want := []Operation{{Op: OpSet, Path: "containers[name=web].securityContext.runAsNonRoot", Value: true}}
	if got := r.Plan(named); !reflect.DeepEqual(got, want) {
		t.Errorf("Plan = %#v, want %#v", got, want)
	}

	unnamed := event(events.KindProcessExec, 0, &events.ProcessExec{Filename: "/bin/sh"},
		&events.Container{ID: containerID})
	want[0].Path = "containers[*].securityContext.runAsNonRoot"
	if got := r.Plan(unnamed); !reflect.DeepEqual(got, want) {
		t.Errorf("Plan = %#v, want %#v", got, want)
	}
}

func TestDefaultRulesAreWellFormed(t *testing.T) {
	idRe := regexp.MustCompile(`^AEG-[0-9]{3}$`)
	seen := map[string]bool{}
	ev := event(events.KindProcessExec, 0, nil, &events.Container{ID: containerID, Name: "web"})
	for _, r := range DefaultRules() {
		if !idRe.MatchString(r.ID) || seen[r.ID] {
			t.Errorf("rule ID %q is malformed or repeated", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" || r.Description == "" || !r.Severity.Valid() {
			t.Errorf("rule %s lacks a title, a description or a valid severity", r.ID)
		}
		plan := r.Plan(ev)
		if len(plan) == 0 {
			t.Errorf("rule %s has an empty plan", r.ID)
		}
		if _, err := compile(plan); err != nil {
			t.Errorf("rule %s: %v", r.ID, err)
		}
	}
}
