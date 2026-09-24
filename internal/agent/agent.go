// Package agent implements the Aegis-eBPF control plane. It ingests the
// events reported by the eBPF probe, evaluates them against the rules of the
// syntactic fixer and keeps the resulting remediations, all in memory. Its
// HTTP API is specified in api/openapi.yaml.
package agent

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/fixer"
)

// ErrNotFound reports an unknown or evicted event or remediation.
var ErrNotFound = errors.New("agent: not found")

// Config configures an Agent. The zero value is ready to use.
type Config struct {
	// MaxEvents bounds the number of recent events kept; the oldest are
	// evicted first. Defaults to 10000.
	MaxEvents int
	// MaxRemediations bounds the number of remediations kept; the least
	// recently seen are evicted first. Defaults to 10000.
	MaxRemediations int
	// Rules defaults to fixer.DefaultRules.
	Rules  []*fixer.Rule
	Logger *slog.Logger
}

// Remediation aggregates every match of one rule for one container.
type Remediation struct {
	ID          string            `json:"id"`
	Rule        *fixer.Rule       `json:"rule"`
	Container   events.Container  `json:"container"`
	EventID     string            `json:"event_id"`
	Occurrences int               `json:"occurrences"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Operations  []fixer.Operation `json:"operations"`
}

// Agent is the control plane. It is safe for concurrent use.
type Agent struct {
	rules   []*fixer.Rule
	log     *slog.Logger
	maxRems int

	mu     sync.RWMutex
	ring   []events.Event // recent events; ring[head] is the next slot to write
	head   int
	stored int
	byID   map[string]int // event ID to position in ring
	rems   map[string]*Remediation
	remFor map[remKey]*Remediation
}

type remKey struct{ rule, container string }

// New returns an Agent configured by cfg.
func New(cfg Config) *Agent {
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 10000
	}
	if cfg.MaxRemediations <= 0 {
		cfg.MaxRemediations = 10000
	}
	if cfg.Rules == nil {
		cfg.Rules = fixer.DefaultRules()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Agent{
		rules:   cfg.Rules,
		log:     cfg.Logger,
		maxRems: cfg.MaxRemediations,
		ring:    make([]events.Event, cfg.MaxEvents),
		byID:    make(map[string]int),
		rems:    make(map[string]*Remediation),
		remFor:  make(map[remKey]*Remediation),
	}
}

// InvalidEventError reports why the event at Index of a batch is invalid.
type InvalidEventError struct {
	Index int
	Err   error
}

func (e *InvalidEventError) Error() string { return fmt.Sprintf("event %d: %v", e.Index, e.Err) }
func (e *InvalidEventError) Unwrap() error { return e.Err }

// Ingest validates, classifies and stores a batch of events, and returns the
// IDs assigned to them. The batch is atomic: if an event is invalid, Ingest
// stores nothing and returns one *InvalidEventError per invalid event,
// joined.
func (a *Agent) Ingest(batch []events.Event) ([]string, error) {
	var errs []error
	for i := range batch {
		if err := batch[i].Validate(); err != nil {
			errs = append(errs, &InvalidEventError{Index: i, Err: err})
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	ids := make([]string, len(batch))
	for i := range batch {
		ev := batch[i]
		ev.ID = newID()
		ev.Severity = events.SeverityInfo
		for _, r := range a.rules {
			if !r.Matches(&ev) {
				continue
			}
			if r.Severity.Rank() > ev.Severity.Rank() {
				ev.Severity = r.Severity
			}
			if ev.Container != nil { // plans patch the pod of a container
				a.recordLocked(r, &ev)
			}
		}
		a.storeLocked(ev)
		ids[i] = ev.ID
	}
	return ids, nil
}

func (a *Agent) storeLocked(ev events.Event) {
	if a.stored == len(a.ring) {
		delete(a.byID, a.ring[a.head].ID)
	} else {
		a.stored++
	}
	a.ring[a.head] = ev
	a.byID[ev.ID] = a.head
	a.head = (a.head + 1) % len(a.ring)
}

// recordLocked adds ev, which matched r, to the remediation of r for the
// container of ev.
func (a *Agent) recordLocked(r *fixer.Rule, ev *events.Event) {
	key := remKey{r.ID, ev.Container.ID}
	if rem, ok := a.remFor[key]; ok {
		rem.Occurrences++
		if ev.Time.Before(rem.FirstSeen) {
			rem.FirstSeen = ev.Time
		}
		if ev.Time.After(rem.LastSeen) {
			rem.LastSeen = ev.Time
		}
		return
	}
	if len(a.rems) >= a.maxRems {
		a.evictRemediationLocked()
	}
	rem := &Remediation{
		ID:          newID(),
		Rule:        r,
		Container:   *ev.Container,
		EventID:     ev.ID,
		Occurrences: 1,
		FirstSeen:   ev.Time,
		LastSeen:    ev.Time,
		Operations:  r.Plan(ev),
	}
	a.rems[rem.ID] = rem
	a.remFor[key] = rem
	a.log.Info("remediation opened", "remediation", rem.ID, "rule", r.ID,
		"severity", r.Severity, "container", ev.Container.ID, "event", ev.ID)
}

// evictRemediationLocked drops the least recently seen remediation.
func (a *Agent) evictRemediationLocked() {
	var oldest *Remediation
	for _, rem := range a.rems {
		if oldest == nil || rem.LastSeen.Before(oldest.LastSeen) {
			oldest = rem
		}
	}
	delete(a.rems, oldest.ID)
	delete(a.remFor, remKey{oldest.Rule.ID, oldest.Container.ID})
}

// EventFilter selects events. Zero fields match everything.
type EventFilter struct {
	Kind        events.Kind
	MinSeverity events.Severity
	ContainerID string
	Limit       int
}

// Events returns the stored events that match f, newest first.
func (a *Agent) Events(f EventFilter) []events.Event {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := []events.Event{}
	for i := 1; i <= a.stored && (f.Limit <= 0 || len(out) < f.Limit); i++ {
		ev := a.ring[(a.head-i+len(a.ring))%len(a.ring)]
		if f.Kind != "" && ev.Kind != f.Kind ||
			ev.Severity.Rank() < f.MinSeverity.Rank() ||
			f.ContainerID != "" && (ev.Container == nil || ev.Container.ID != f.ContainerID) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// Event returns the stored event with the given ID.
func (a *Agent) Event(id string) (events.Event, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	i, ok := a.byID[id]
	if !ok {
		return events.Event{}, ErrNotFound
	}
	return a.ring[i], nil
}

// RemediationFilter selects remediations. Zero fields match everything.
type RemediationFilter struct {
	MinSeverity events.Severity
	ContainerID string
	Limit       int
}

// Remediations returns the remediations that match f, most recently seen
// first.
func (a *Agent) Remediations(f RemediationFilter) []Remediation {
	a.mu.RLock()
	out := []Remediation{}
	for _, rem := range a.rems {
		if rem.Rule.Severity.Rank() >= f.MinSeverity.Rank() &&
			(f.ContainerID == "" || rem.Container.ID == f.ContainerID) {
			out = append(out, *rem)
		}
	}
	a.mu.RUnlock()
	slices.SortFunc(out, func(x, y Remediation) int {
		if c := y.LastSeen.Compare(x.LastSeen); c != 0 {
			return c
		}
		return cmp.Compare(y.ID, x.ID)
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}

// Remediation returns the remediation with the given ID.
func (a *Agent) Remediation(id string) (Remediation, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	rem, ok := a.rems[id]
	if !ok {
		return Remediation{}, ErrNotFound
	}
	return *rem, nil
}

// Patch applies the plan of the remediation with the given ID to manifest.
func (a *Agent) Patch(id string, manifest []byte) (*fixer.Result, error) {
	rem, err := a.Remediation(id)
	if err != nil {
		return nil, err
	}
	return fixer.Apply(manifest, rem.Operations)
}

// newID returns a random, time-ordered UUID (version 7, RFC 9562).
func newID() string {
	var b [16]byte
	rand.Read(b[6:]) // never fails; see crypto/rand.Read
	ms := uint64(time.Now().UnixMilli())
	for i := range 6 {
		b[i] = byte(ms >> (40 - 8*i))
	}
	b[6] = b[6]&0x0f | 0x70 // version 7
	b[8] = b[8]&0x3f | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
