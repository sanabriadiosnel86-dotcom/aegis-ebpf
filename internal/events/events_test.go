package events

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const containerID = "2d1f6c4a9e8b7d0c3f5a6b1e4d7c0a9f8e2b5d6c1a4f7e0b3d9c2a5f8e1b4d7c"

func TestUnmarshalSelectsDataByKind(t *testing.T) {
	tests := []struct {
		json string
		want Data
	}{
		{
			`{"kind":"process_exec","data":{"filename":"/bin/sh","argv":["sh","-c","id"]}}`,
			&ProcessExec{Filename: "/bin/sh", Argv: []string{"sh", "-c", "id"}},
		},
		{
			`{"kind":"file_open","data":{"path":"/etc/shadow","flags":["O_WRONLY","O_TRUNC"]}}`,
			&FileOpen{Path: "/etc/shadow", Flags: []string{"O_WRONLY", "O_TRUNC"}},
		},
		{
			`{"kind":"privilege_escalation","data":{"syscall":"setresuid","old_uid":1000,"new_uid":0}}`,
			&PrivilegeEscalation{Syscall: "setresuid", OldUID: 1000, NewUID: 0},
		},
		{`{"kind":"unknown","data":{"filename":"/bin/sh"}}`, nil},
		{`{"kind":"process_exec"}`, nil},
		{`{"kind":"process_exec","data":null}`, nil},
	}
	for _, tt := range tests {
		var ev Event
		if err := json.Unmarshal([]byte(tt.json), &ev); err != nil {
			t.Errorf("Unmarshal(%s): %v", tt.json, err)
			continue
		}
		if !reflect.DeepEqual(ev.Data, tt.want) {
			t.Errorf("Unmarshal(%s).Data = %#v, want %#v", tt.json, ev.Data, tt.want)
		}
	}

	var ev Event
	if err := json.Unmarshal([]byte(`{"kind":"file_open","data":{"path":42}}`), &ev); err == nil {
		t.Error("Unmarshal accepted a data member of the wrong type")
	}
}

func TestEventRoundTrip(t *testing.T) {
	in := validEvent()
	in.ID = "01920a4b-7c3d-7e5f-8a9b-0c1d2e3f4a5b"
	in.Severity = SeverityHigh
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Event
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&out, in) {
		t.Errorf("round trip through %s = %#v, want %#v", b, out, *in)
	}
}

func TestValidate(t *testing.T) {
	if err := validEvent().Validate(); err != nil {
		t.Fatalf("Validate() of a valid event: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Event)
		want   string
	}{
		{"unknown kind", func(e *Event) { e.Kind = "exec"; e.Data = nil }, `kind "exec"`},
		{"missing time", func(e *Event) { e.Time = time.Time{} }, "time is required"},
		{"missing node", func(e *Event) { e.Node = "" }, "node"},
		{"zero pid", func(e *Event) { e.Process.PID = 0 }, "process.pid"},
		{"long comm", func(e *Event) { e.Process.Comm = strings.Repeat("x", 65) }, "process.comm"},
		{"short container id", func(e *Event) { e.Container.ID = "2d1f6c4a9e8b" }, "container.id"},
		{"unknown runtime", func(e *Event) { e.Container.Runtime = "lxc" }, "container.runtime"},
		{"invalid container name", func(e *Event) { e.Container.Name = "Web_1" }, "container.name"},
		{"invalid pod uid", func(e *Event) { e.Container.Pod = &Pod{UID: "pod-1"} }, "container.pod.uid"},
		{"missing data", func(e *Event) { e.Data = nil }, "data is required"},
		{"mismatched data", func(e *Event) { e.Kind = KindFileOpen }, "data holds a process_exec payload but kind is file_open"},
		{"empty filename", func(e *Event) { e.Data = &ProcessExec{} }, "data.filename"},
		{"unknown flag", func(e *Event) {
			e.Kind, e.Data = KindFileOpen, &FileOpen{Path: "/etc/passwd", Flags: []string{"O_SYNC"}}
		}, `"O_SYNC" is not one of`},
		{"repeated flag", func(e *Event) {
			e.Kind, e.Data = KindFileOpen, &FileOpen{Path: "/etc/passwd", Flags: []string{"O_RDWR", "O_RDWR"}}
		}, `"O_RDWR" is repeated`},
		{"unknown syscall", func(e *Event) {
			e.Kind, e.Data = KindPrivilegeEscalation, &PrivilegeEscalation{Syscall: "setgid"}
		}, "data.syscall"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := validEvent()
			tt.mutate(ev)
			err := ev.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate() = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestSeverityRank(t *testing.T) {
	if !(SeverityInfo.Rank() < SeverityLow.Rank() && SeverityLow.Rank() < SeverityMedium.Rank() &&
		SeverityMedium.Rank() < SeverityHigh.Rank() && SeverityHigh.Rank() < SeverityCritical.Rank()) {
		t.Error("severities are not ranked in ascending order")
	}
	if Severity("urgent").Valid() {
		t.Error(`Severity("urgent") is valid`)
	}
}

func validEvent() *Event {
	return &Event{
		Kind:    KindProcessExec,
		Time:    time.Date(2026, 9, 23, 23, 1, 2, 123456789, time.UTC),
		Node:    "worker-1",
		Process: Process{PID: 4242, PPID: 4100, Comm: "sh", CgroupID: 7},
		Container: &Container{
			ID:      containerID,
			Runtime: "containerd",
			Name:    "web",
			Pod:     &Pod{UID: "6c3b1f0e-5d4a-4f2b-9e8d-7c6b5a4f3e2d", Name: "web-7d9f", Namespace: "shop"},
		},
		Data: &ProcessExec{Filename: "/bin/sh", Argv: []string{"sh", "-c", "id"}},
	}
}
