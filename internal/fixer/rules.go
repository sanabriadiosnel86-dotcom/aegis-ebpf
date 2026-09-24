package fixer

import (
	"path"
	"strings"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
)

// Rule detects a dangerous runtime behavior and knows how to harden the
// workload that exhibited it.
type Rule struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    events.Severity `json:"severity"`

	match func(*events.AuditEvent) bool
	// fix lists the operations of the plan, with paths relative to the
	// offending container.
	fix []Operation
}

// Matches reports whether ev triggers r.
func (r *Rule) Matches(ev *events.AuditEvent) bool { return r.match(ev) }

// Plan returns the operations that harden the workload running the container
// of ev. They target that container when its name is known, and every
// container of the pod otherwise.
func (r *Rule) Plan(ev *events.AuditEvent) []Operation {
	target := "containers[*]"
	if c := ev.Container; c != nil && c.Name != "" {
		target = "containers[name=" + c.Name + "]"
	}
	ops := make([]Operation, len(r.fix))
	for i, op := range r.fix {
		ops[i] = Operation{Op: op.Op, Path: target + "." + op.Path, Value: op.Value}
	}
	return ops
}

// systemDirs are the directories that a container should never write to.
var systemDirs = []string{"/bin", "/boot", "/etc", "/lib", "/lib32", "/lib64", "/root", "/sbin", "/usr"}

// DefaultRules returns the built-in rules. Every rule applies to processes
// running in a container only, since its plan patches a pod spec.
func DefaultRules() []*Rule {
	return []*Rule{
		{
			ID:       "AEG-001",
			Title:    "Container process running as root",
			Severity: events.SeverityMedium,
			Description: "A process started with UID 0 inside a container. Require a non-root " +
				"user, so that a compromised process does not start as root. The image " +
				"must define a non-root USER, or the pod must set runAsUser.",
			match: func(ev *events.AuditEvent) bool {
				return ev.Kind == events.KindProcessExec && ev.Container != nil && ev.Process.UID == 0
			},
			fix: []Operation{
				{Op: OpSet, Path: "securityContext.runAsNonRoot", Value: true},
			},
		},
		{
			ID:       "AEG-002",
			Title:    "Privilege escalation to root",
			Severity: events.SeverityCritical,
			Description: "A process inside a container changed its real UID to 0. Forbid " +
				"privilege escalation (no_new_privs blocks setuid binaries) and drop " +
				"every Linux capability, including CAP_SETUID.",
			match: func(ev *events.AuditEvent) bool {
				return ev.Kind == events.KindPrivilegeEscalation && ev.Container != nil
			},
			fix: []Operation{
				{Op: OpSet, Path: "securityContext.allowPrivilegeEscalation", Value: false},
				{Op: OpAdd, Path: "securityContext.capabilities.drop", Value: "ALL"},
			},
		},
		{
			ID:       "AEG-003",
			Title:    "Write to a system directory",
			Severity: events.SeverityHigh,
			Description: "A process inside a container opened a file under a system directory " +
				"for writing. Mount the root filesystem read-only, and give the workload " +
				"emptyDir volumes where it legitimately writes.",
			match: func(ev *events.AuditEvent) bool {
				d, ok := ev.Data.(*events.FileOpen)
				return ok && ev.Container != nil && underSystemDir(d.Path)
			},
			fix: []Operation{
				{Op: OpSet, Path: "securityContext.readOnlyRootFilesystem", Value: true},
			},
		},
	}
}

// underSystemDir reports whether the absolute path p lies in one of
// systemDirs. Relative paths never match: their directory is unknown.
func underSystemDir(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	p = path.Clean(p)
	for _, dir := range systemDirs {
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return false
}
