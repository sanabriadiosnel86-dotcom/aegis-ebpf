package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/fixer"
)

const (
	maxBatch        = 1000    // events per ingestion request
	maxEventsBody   = 4 << 20 // bytes
	maxManifestBody = 1 << 20 // bytes
	defaultLimit    = 100
	maxLimit        = 1000
)

// Handler returns the HTTP API of a, as specified in api/openapi.yaml.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /v1/events", a.ingestEvents)
	mux.HandleFunc("GET /v1/events", a.listEvents)
	mux.HandleFunc("GET /v1/events/{id}", a.getEvent)
	mux.HandleFunc("GET /v1/remediations", a.listRemediations)
	mux.HandleFunc("GET /v1/remediations/{id}", a.getRemediation)
	mux.HandleFunc("POST /v1/remediations/{id}/patch", a.patchManifest)
	return mux
}

type ingestResult struct {
	Accepted int      `json:"accepted"`
	IDs      []string `json:"ids"`
}

type list[T any] struct {
	Items []T `json:"items"`
}

type patchResult struct {
	RemediationID string                `json:"remediation_id"`
	Manifest      string                `json:"manifest"`
	Documents     []fixer.DocumentPatch `json:"documents"`
}

// problem is an RFC 9457 problem details object.
type problem struct {
	Title  string       `json:"title"`
	Status int          `json:"status"`
	Detail string       `json:"detail,omitempty"`
	Errors []fieldError `json:"errors,omitempty"`
}

type fieldError struct {
	Index   int    `json:"index"`
	Message string `json:"message"`
}

func (a *Agent) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *Agent) ingestEvents(w http.ResponseWriter, r *http.Request) {
	if !hasContentType(r, "application/json") {
		writeProblem(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var batch struct {
		Events []events.Event `json:"events"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEventsBody)).Decode(&batch); err != nil {
		writeBodyError(w, err)
		return
	}
	if n := len(batch.Events); n == 0 || n > maxBatch {
		writeProblem(w, http.StatusBadRequest, fmt.Sprintf("events must hold 1 to %d items, not %d", maxBatch, n))
		return
	}
	ids, err := a.Ingest(batch.Events)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "the batch has invalid events; none was stored", fieldErrors(err)...)
		return
	}
	writeJSON(w, http.StatusAccepted, ingestResult{Accepted: len(ids), IDs: ids})
}

func (a *Agent) listEvents(w http.ResponseWriter, r *http.Request) {
	q, err := parseListQuery(r.URL.Query())
	kind := events.Kind(r.URL.Query().Get("kind"))
	if err == nil && kind != "" && !kind.Valid() {
		err = fmt.Errorf("kind must be one of %v", events.Kinds())
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, err.Error())
		return
	}
	evs := a.Events(EventFilter{Kind: kind, MinSeverity: q.minSeverity, ContainerID: q.containerID, Limit: q.limit})
	writeJSON(w, http.StatusOK, list[events.Event]{Items: evs})
}

func (a *Agent) getEvent(w http.ResponseWriter, r *http.Request) {
	ev, err := a.Event(r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "no event has this ID; it may have been evicted")
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (a *Agent) listRemediations(w http.ResponseWriter, r *http.Request) {
	q, err := parseListQuery(r.URL.Query())
	if err != nil {
		writeProblem(w, http.StatusBadRequest, err.Error())
		return
	}
	rems := a.Remediations(RemediationFilter{MinSeverity: q.minSeverity, ContainerID: q.containerID, Limit: q.limit})
	writeJSON(w, http.StatusOK, list[Remediation]{Items: rems})
}

func (a *Agent) getRemediation(w http.ResponseWriter, r *http.Request) {
	rem, err := a.Remediation(r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "no remediation has this ID; it may have been evicted")
		return
	}
	writeJSON(w, http.StatusOK, rem)
}

func (a *Agent) patchManifest(w http.ResponseWriter, r *http.Request) {
	if !hasContentType(r, "application/yaml", "application/x-yaml", "text/yaml") {
		writeProblem(w, http.StatusUnsupportedMediaType, "Content-Type must be application/yaml")
		return
	}
	manifest, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxManifestBody))
	if err != nil {
		writeBodyError(w, err)
		return
	}
	id := r.PathValue("id")
	res, err := a.Patch(id, manifest)
	switch {
	case errors.Is(err, ErrNotFound):
		writeProblem(w, http.StatusNotFound, "no remediation has this ID; it may have been evicted")
	case errors.Is(err, fixer.ErrSyntax):
		writeProblem(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, fixer.ErrNoWorkload), errors.Is(err, fixer.ErrConflict):
		writeProblem(w, http.StatusUnprocessableEntity, err.Error())
	case err != nil:
		a.log.Error("patching a manifest failed", "remediation", id, "error", err)
		writeProblem(w, http.StatusInternalServerError, "the manifest could not be patched")
	default:
		docs := res.Documents
		if docs == nil {
			docs = []fixer.DocumentPatch{}
		}
		writeJSON(w, http.StatusOK, patchResult{RemediationID: id, Manifest: string(res.Manifest), Documents: docs})
	}
}

type listQuery struct {
	minSeverity events.Severity
	containerID string
	limit       int
}

// parseListQuery parses the query parameters shared by the list endpoints.
func parseListQuery(v url.Values) (listQuery, error) {
	q := listQuery{
		minSeverity: events.Severity(v.Get("min_severity")),
		containerID: v.Get("container_id"),
		limit:       defaultLimit,
	}
	if q.minSeverity != "" && !q.minSeverity.Valid() {
		return q, fmt.Errorf("min_severity must be one of %v", events.Severities())
	}
	if q.containerID != "" && !events.ValidContainerID(q.containerID) {
		return q, errors.New("container_id must be 64 lowercase hexadecimal characters")
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxLimit {
			return q, fmt.Errorf("limit must be an integer from 1 to %d", maxLimit)
		}
		q.limit = n
	}
	return q, nil
}

// fieldErrors flattens the error returned by Ingest: one entry per violation
// of every invalid event.
func fieldErrors(err error) []fieldError {
	var out []fieldError
	for _, e := range unjoin(err) {
		var inv *InvalidEventError
		if errors.As(e, &inv) {
			for _, v := range unjoin(inv.Err) {
				out = append(out, fieldError{Index: inv.Index, Message: v.Error()})
			}
		}
	}
	return out
}

func unjoin(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}

func hasContentType(r *http.Request, want ...string) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && slices.Contains(want, mt)
}

func writeBodyError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeProblem(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("the body exceeds %d bytes", tooLarge.Limit))
		return
	}
	writeProblem(w, http.StatusBadRequest, "invalid body: "+err.Error())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // fails only when the client is gone
}

func writeProblem(w http.ResponseWriter, status int, detail string, errs ...fieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Title: http.StatusText(status), Status: status, Detail: detail, Errors: errs})
}
