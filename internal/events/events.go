// Package events defines the audit events that the eBPF probe reports to the
// control plane. The wire format is specified in api/openapi.yaml.
package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"
)

// Kind identifies the kernel activity that an AuditEvent describes.
type Kind string

const (
	KindProcessExec         Kind = "process_exec"
	KindFileOpen            Kind = "file_open"
	KindPrivilegeEscalation Kind = "privilege_escalation"
	KindNetworkConnect      Kind = "network_connect"
	KindPtrace              Kind = "ptrace"
)

// Kinds returns every known Kind.
func Kinds() []Kind {
	return []Kind{KindProcessExec, KindFileOpen, KindPrivilegeEscalation, KindNetworkConnect, KindPtrace}
}

// Valid reports whether k is a known Kind.
func (k Kind) Valid() bool { return slices.Contains(Kinds(), k) }

// Severity ranks how dangerous an event is.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Severities returns every known Severity, from least to most severe.
func Severities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

// Rank returns the position of s in Severities, or -1 if s is unknown.
func (s Severity) Rank() int { return slices.Index(Severities(), s) }

// Valid reports whether s is a known Severity.
func (s Severity) Valid() bool { return s.Rank() >= 0 }

// AuditEvent is a security-relevant kernel event, recorded for audit.
type AuditEvent struct {
	// ID and Severity are assigned by the agent on ingestion.
	ID        string     `json:"id"`
	Kind      Kind       `json:"kind"`
	Time      time.Time  `json:"time"`
	Node      string     `json:"node"`
	Severity  Severity   `json:"severity"`
	Process   Process    `json:"process"`
	Container *Container `json:"container,omitempty"`
	// Data holds the payload that matches Kind.
	Data Data `json:"data"`
}

// Data is the kind-specific payload of an AuditEvent: *ProcessExec,
// *FileOpen, *PrivilegeEscalation, *NetworkConnect or *Ptrace.
type Data interface {
	Kind() Kind
	validate() []error
}

// ProcessExec is the payload of KindProcessExec events.
type ProcessExec struct {
	Filename string   `json:"filename"`
	Argv     []string `json:"argv,omitempty"`
	// ArgvTruncated is set when the command line had more arguments than
	// the probe captures.
	ArgvTruncated bool `json:"argv_truncated,omitempty"`
}

// FileOpen is the payload of KindFileOpen events.
type FileOpen struct {
	Path  string   `json:"path"`
	Flags []string `json:"flags"`
}

// PrivilegeEscalation is the payload of KindPrivilegeEscalation events.
type PrivilegeEscalation struct {
	Syscall string `json:"syscall"`
	OldUID  uint32 `json:"old_uid"`
	NewUID  uint32 `json:"new_uid"`
}

// NetworkConnect is the payload of KindNetworkConnect events: an outbound
// connect(2) to an IP address.
type NetworkConnect struct {
	// Family is "ipv4" or "ipv6".
	Family  string `json:"family"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	FD      int32  `json:"fd"`
}

// Ptrace is the payload of KindPtrace events: a ptrace(2) call against
// another process.
type Ptrace struct {
	// Request names the operation, such as "PTRACE_ATTACH";
	// "PTRACE_UNKNOWN" when the probe does not know it.
	Request string `json:"request"`
	// RequestCode is the request as the kernel received it.
	RequestCode int64 `json:"request_code"`
	// TargetPID is the pid argument as the caller passed it, in the caller's
	// PID namespace: inside a container it differs from Process.PID, which
	// is in the node's namespace.
	TargetPID int32 `json:"target_pid"`
	// Addr is the address argument, in hexadecimal.
	Addr string `json:"addr"`
}

// Process describes the task that caused an event.
type Process struct {
	PID      int32  `json:"pid"`
	PPID     int32  `json:"ppid,omitempty"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	Comm     string `json:"comm"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`
}

// Container describes the container a process belongs to.
type Container struct {
	ID      string `json:"id"`
	Runtime string `json:"runtime,omitempty"`
	Name    string `json:"name,omitempty"`
	Pod     *Pod   `json:"pod,omitempty"`
}

// Pod describes the Kubernetes pod that runs a container.
type Pod struct {
	UID       string `json:"uid,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

func (*ProcessExec) Kind() Kind         { return KindProcessExec }
func (*FileOpen) Kind() Kind            { return KindFileOpen }
func (*PrivilegeEscalation) Kind() Kind { return KindPrivilegeEscalation }
func (*NetworkConnect) Kind() Kind      { return KindNetworkConnect }
func (*Ptrace) Kind() Kind              { return KindPtrace }

func newData(k Kind) Data {
	switch k {
	case KindProcessExec:
		return new(ProcessExec)
	case KindFileOpen:
		return new(FileOpen)
	case KindPrivilegeEscalation:
		return new(PrivilegeEscalation)
	case KindNetworkConnect:
		return new(NetworkConnect)
	case KindPtrace:
		return new(Ptrace)
	}
	return nil
}

// UnmarshalJSON decodes the "data" member according to "kind". An unknown
// kind leaves Data nil; Validate reports it.
func (e *AuditEvent) UnmarshalJSON(b []byte) error {
	type plain AuditEvent // drops the methods, avoiding recursion
	var aux struct {
		plain
		Data json.RawMessage `json:"data"` // shadows plain.Data
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*e = AuditEvent(aux.plain)
	d := newData(e.Kind)
	if d == nil || len(aux.Data) == 0 || string(aux.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(aux.Data, d); err != nil {
		return fmt.Errorf("data: %w", err)
	}
	e.Data = d
	return nil
}

var (
	containerIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dnsLabelRe    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	uuidRe        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// ValidContainerID reports whether id is a full, 64-character container ID.
func ValidContainerID(id string) bool { return containerIDRe.MatchString(id) }

// Validate checks e against the constraints of api/openapi.yaml, as for an
// event received from a probe: it ignores ID and Severity. The returned error
// joins one error per violation.
func (e *AuditEvent) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if !e.Kind.Valid() {
		fail("kind %q is not one of %v", e.Kind, Kinds())
	}
	if e.Time.IsZero() {
		fail("time is required")
	}
	if !lengthIn(e.Node, 1, 253) {
		fail("node must have 1 to 253 characters")
	}
	if e.Process.PID < 1 {
		fail("process.pid must be positive")
	}
	if e.Process.PPID < 0 {
		fail("process.ppid must not be negative")
	}
	if !lengthIn(e.Process.Comm, 0, 64) {
		fail("process.comm must have at most 64 characters")
	}
	if c := e.Container; c != nil {
		errs = append(errs, c.validate()...)
	}
	switch {
	case e.Data == nil:
		if e.Kind.Valid() {
			fail("data is required")
		}
	case e.Data.Kind() != e.Kind:
		fail("data holds a %s payload but kind is %s", e.Data.Kind(), e.Kind)
	default:
		errs = append(errs, e.Data.validate()...)
	}
	return errors.Join(errs...)
}

func (c *Container) validate() []error {
	var errs []error
	if !ValidContainerID(c.ID) {
		errs = append(errs, errors.New("container.id must be 64 lowercase hexadecimal characters"))
	}
	switch c.Runtime {
	case "", "docker", "containerd", "cri-o", "podman":
	default:
		errs = append(errs, fmt.Errorf("container.runtime %q is not one of docker, containerd, cri-o, podman", c.Runtime))
	}
	if c.Name != "" && (len(c.Name) > 63 || !dnsLabelRe.MatchString(c.Name)) {
		errs = append(errs, errors.New("container.name must be a DNS label"))
	}
	if p := c.Pod; p != nil {
		if p.UID != "" && !uuidRe.MatchString(p.UID) {
			errs = append(errs, errors.New("container.pod.uid must be a UUID"))
		}
		if p.Name != "" && !lengthIn(p.Name, 1, 253) {
			errs = append(errs, errors.New("container.pod.name must have at most 253 characters"))
		}
		if p.Namespace != "" && !lengthIn(p.Namespace, 1, 63) {
			errs = append(errs, errors.New("container.pod.namespace must have at most 63 characters"))
		}
	}
	return errs
}

func (d *ProcessExec) validate() []error {
	var errs []error
	if !lengthIn(d.Filename, 1, 4096) {
		errs = append(errs, errors.New("data.filename must have 1 to 4096 characters"))
	}
	if len(d.Argv) > 256 {
		errs = append(errs, errors.New("data.argv must have at most 256 items"))
	}
	return errs
}

// OpenFlags returns the open(2) flags that a FileOpen payload may report.
func OpenFlags() []string {
	return []string{"O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}
}

func (d *FileOpen) validate() []error {
	var errs []error
	if !lengthIn(d.Path, 1, 4096) {
		errs = append(errs, errors.New("data.path must have 1 to 4096 characters"))
	}
	if len(d.Flags) == 0 {
		errs = append(errs, errors.New("data.flags must not be empty"))
	}
	seen := make(map[string]bool, len(d.Flags))
	for _, f := range d.Flags {
		if !slices.Contains(OpenFlags(), f) {
			errs = append(errs, fmt.Errorf("data.flags: %q is not one of %v", f, OpenFlags()))
		} else if seen[f] {
			errs = append(errs, fmt.Errorf("data.flags: %q is repeated", f))
		}
		seen[f] = true
	}
	return errs
}

func (d *PrivilegeEscalation) validate() []error {
	switch d.Syscall {
	case "setuid", "setreuid", "setresuid":
		return nil
	}
	return []error{fmt.Errorf("data.syscall %q is not one of setuid, setreuid, setresuid", d.Syscall)}
}

func (d *NetworkConnect) validate() []error {
	addr, err := netip.ParseAddr(d.Address)
	switch {
	case d.Family != "ipv4" && d.Family != "ipv6":
		return []error{fmt.Errorf("data.family %q is not one of ipv4, ipv6", d.Family)}
	case err != nil || addr.Zone() != "":
		return []error{fmt.Errorf("data.address %q is not an IP address", d.Address)}
	case d.Family == "ipv4" && !addr.Is4(), d.Family == "ipv6" && !addr.Is6():
		return []error{fmt.Errorf("data.address %q is not an %s address", d.Address, d.Family)}
	}
	return nil
}

var (
	ptraceRequestRe = regexp.MustCompile(`^PTRACE_[A-Z]+$`)
	hexRe           = regexp.MustCompile(`^0x[0-9a-f]+$`)
)

func (d *Ptrace) validate() []error {
	var errs []error
	if !ptraceRequestRe.MatchString(d.Request) {
		errs = append(errs, fmt.Errorf("data.request %q is not a PTRACE_ request name", d.Request))
	}
	if !hexRe.MatchString(d.Addr) {
		errs = append(errs, fmt.Errorf("data.addr %q is not a hexadecimal address", d.Addr))
	}
	return errs
}

// lengthIn reports whether s has between lo and hi characters, counted as
// JSON Schema does (Unicode code points).
func lengthIn(s string, lo, hi int) bool {
	n := utf8.RuneCountInString(s)
	return lo <= n && n <= hi
}
