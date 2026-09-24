package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"
)

func init() {
	// The spec declares the manifest sent to the patch endpoint as a string:
	// validate it as raw text rather than as a decoded YAML document.
	openapi3filter.RegisterBodyDecoder("application/yaml", openapi3filter.PlainBodyDecoder)
	openapi3.DefineStringFormatValidator("uuid", openapi3.NewRegexpFormatValidator(openapi3.FormatOfStringForUUIDOfRFC9562))
}

// api drives the HTTP handler of an Agent and checks every exchange against
// the OpenAPI specification.
type api struct {
	t      *testing.T
	h      http.Handler
	router routers.Router
}

func newAPI(t *testing.T) *api {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("loading the spec: %v", err)
	}
	// NewRouter validates the spec, examples included. Passing an option
	// matters: without one, kin-openapi validates the examples of request
	// bodies as responses, where readOnly properties are required.
	router, err := legacyrouter.NewRouter(doc, openapi3.EnableExamplesValidation())
	if err != nil {
		t.Fatal(err)
	}
	return &api{t: t, h: New(Config{}).Handler(), router: router}
}

// do sends a request to the handler. It fails the test when the response
// violates the spec, or when the spec does not agree with specValid about
// the validity of the request.
func (c *api) do(method, target, contentType, body string, specValid bool) *httptest.ResponseRecorder {
	c.t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1:8080"+target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	route, params, err := c.router.FindRoute(req)
	if err != nil {
		c.t.Fatalf("%s %s is not in the spec: %v", method, target, err)
	}
	in := &openapi3filter.RequestValidationInput{
		Request: req, PathParams: params, Route: route,
		Options: &openapi3filter.Options{IncludeResponseStatus: true, MultiError: true},
	}
	ctx := context.Background()
	if err := openapi3filter.ValidateRequest(ctx, in); (err == nil) != specValid {
		c.t.Errorf("%s %s: the spec finds the request valid=%v (%v), want %v", method, target, err == nil, err, specValid)
	}

	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	out := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in,
		Status:                 rec.Code,
		Header:                 rec.Header(),
		Body:                   io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
	}
	if err := openapi3filter.ValidateResponse(ctx, out); err != nil {
		c.t.Errorf("%s %s: response %d violates the spec: %v\n%s", method, target, rec.Code, err, rec.Body)
	}
	return rec
}

func expectStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status %d, want %d: %s", rec.Code, want, rec.Body)
	}
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body, err)
	}
	return v
}

// probeBatch is a batch as the probe sends it: without id nor severity.
const probeBatch = `{"events": [
  {
    "kind": "process_exec",
    "time": "2026-09-23T23:01:02.123456789Z",
    "node": "worker-1",
    "process": {"pid": 4242, "ppid": 4100, "uid": 0, "gid": 0, "comm": "sh", "cgroup_id": 7},
    "container": {"id": "` + webID + `", "runtime": "docker"},
    "data": {"filename": "/bin/sh", "argv": ["sh", "-c", "id"]}
  },
  {
    "kind": "privilege_escalation",
    "time": "2026-09-23T23:01:03Z",
    "node": "worker-1",
    "process": {"pid": 4243, "uid": 0, "gid": 1000, "comm": "exploit"},
    "container": {"id": "` + webID + `", "name": "web", "pod": {"uid": "6c3b1f0e-5d4a-4f2b-9e8d-7c6b5a4f3e2d"}},
    "data": {"syscall": "setresuid", "old_uid": 1000, "new_uid": 0}
  },
  {
    "kind": "file_open",
    "time": "2026-09-23T23:01:04Z",
    "node": "worker-1",
    "process": {"pid": 1, "uid": 0, "gid": 0, "comm": "systemd"},
    "data": {"path": "/etc/machine-id", "flags": ["O_WRONLY", "O_CREAT", "O_TRUNC"]}
  },
  {
    "kind": "network_connect",
    "time": "2026-09-23T23:01:05Z",
    "node": "worker-1",
    "process": {"pid": 4250, "uid": 1000, "gid": 1000, "comm": "curl"},
    "container": {"id": "` + webID + `"},
    "data": {"family": "ipv6", "address": "2001:db8::1", "port": 443, "fd": 5}
  },
  {
    "kind": "ptrace",
    "time": "2026-09-23T23:01:06Z",
    "node": "worker-1",
    "process": {"pid": 4251, "uid": 0, "gid": 0, "comm": "gdb"},
    "container": {"id": "` + webID + `"},
    "data": {"request": "PTRACE_ATTACH", "request_code": 16, "target_pid": 4242, "addr": "0x0"}
  }
]}`

const deployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: web # public frontend
        image: nginx:1.27
`

func TestHTTPEventsAndRemediations(t *testing.T) {
	c := newAPI(t)

	rec := c.do("GET", "/healthz", "", "", true)
	expectStatus(t, rec, http.StatusOK)

	rec = c.do("POST", "/v1/events", "application/json", probeBatch, true)
	expectStatus(t, rec, http.StatusAccepted)
	ingested := decodeBody[ingestResult](t, rec)
	if ingested.Accepted != 5 || len(ingested.IDs) != 5 {
		t.Fatalf("ingestion result = %+v, want 5 accepted events", ingested)
	}

	rec = c.do("GET", "/v1/events", "", "", true)
	expectStatus(t, rec, http.StatusOK)
	all := decodeBody[list[json.RawMessage]](t, rec).Items
	if len(all) != 5 {
		t.Errorf("listed %d events, want 5", len(all))
	}

	rec = c.do("GET", "/v1/events?kind=privilege_escalation&min_severity=critical&container_id="+webID+"&limit=10", "", "", true)
	expectStatus(t, rec, http.StatusOK)
	if items := decodeBody[list[json.RawMessage]](t, rec).Items; len(items) != 1 {
		t.Errorf("filtered listing returned %d events, want 1", len(items))
	}

	for _, kind := range []string{"network_connect", "ptrace"} {
		rec = c.do("GET", "/v1/events?kind="+kind, "", "", true)
		expectStatus(t, rec, http.StatusOK)
		items := decodeBody[list[map[string]any]](t, rec).Items
		if len(items) != 1 || items[0]["severity"] != "info" {
			t.Errorf("events of kind %s = %v, want one with severity info", kind, items)
		}
	}

	rec = c.do("GET", "/v1/events/"+ingested.IDs[1], "", "", true)
	expectStatus(t, rec, http.StatusOK)
	if ev := decodeBody[map[string]any](t, rec); ev["severity"] != "critical" || ev["id"] != ingested.IDs[1] {
		t.Errorf("event = %v, want the critical escalation", ev)
	}

	rec = c.do("GET", "/v1/events/00000000-0000-7000-8000-000000000000", "", "", true)
	expectStatus(t, rec, http.StatusNotFound)

	rec = c.do("GET", "/v1/remediations?min_severity=critical", "", "", true)
	expectStatus(t, rec, http.StatusOK)
	rems := decodeBody[list[Remediation]](t, rec).Items
	if len(rems) != 1 || rems[0].Rule.ID != "AEG-002" || rems[0].EventID != ingested.IDs[1] {
		t.Fatalf("critical remediations = %+v, want the AEG-002 one", rems)
	}
	remURL := "/v1/remediations/" + rems[0].ID

	rec = c.do("GET", "/v1/remediations", "", "", true)
	expectStatus(t, rec, http.StatusOK)
	if n := len(decodeBody[list[Remediation]](t, rec).Items); n != 2 {
		t.Errorf("listed %d remediations, want AEG-001 and AEG-002", n)
	}

	rec = c.do("GET", remURL, "", "", true)
	expectStatus(t, rec, http.StatusOK)

	rec = c.do("POST", remURL+"/patch", "application/yaml", deployment, true)
	expectStatus(t, rec, http.StatusOK)
	patched := decodeBody[patchResult](t, rec)
	const wantManifest = deployment + `        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
`
	if patched.Manifest != wantManifest {
		t.Errorf("patched manifest:\n%s\nwant:\n%s", patched.Manifest, wantManifest)
	}
	if len(patched.Documents) != 1 || len(patched.Documents[0].Patch) != 2 {
		t.Errorf("documents = %+v, want one document with two operations", patched.Documents)
	}

	// Patching the fixed manifest changes nothing.
	rec = c.do("POST", remURL+"/patch", "application/yaml", patched.Manifest, true)
	expectStatus(t, rec, http.StatusOK)
	if again := decodeBody[patchResult](t, rec); len(again.Documents) != 0 || again.Manifest != patched.Manifest {
		t.Errorf("second patch = %+v, want no change", again)
	}

	rec = c.do("POST", remURL+"/patch", "application/yaml", "kind: Service\nspec: {}\n", true)
	expectStatus(t, rec, http.StatusUnprocessableEntity)
	rec = c.do("POST", remURL+"/patch", "application/yaml", "kind: [\n", true)
	expectStatus(t, rec, http.StatusBadRequest)
	rec = c.do("POST", remURL+"/patch", "application/json", `{"kind": "Pod"}`, false)
	expectStatus(t, rec, http.StatusUnsupportedMediaType)
	rec = c.do("POST", "/v1/remediations/00000000-0000-7000-8000-000000000000/patch", "application/yaml", deployment, true)
	expectStatus(t, rec, http.StatusNotFound)
}

func TestHTTPRejectsInvalidRequests(t *testing.T) {
	c := newAPI(t)
	tests := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		want        int
	}{
		{"wrong content type", "POST", "/v1/events", "text/plain", probeBatch, http.StatusUnsupportedMediaType},
		{"malformed JSON", "POST", "/v1/events", "application/json", `{"events": [`, http.StatusBadRequest},
		{"empty batch", "POST", "/v1/events", "application/json", `{"events": []}`, http.StatusBadRequest},
		{"invalid event", "POST", "/v1/events", "application/json",
			strings.Replace(probeBatch, `"pid": 4242`, `"pid": 0`, 1), http.StatusBadRequest},
		{"oversized body", "POST", "/v1/events", "application/json",
			`{"pad": "` + strings.Repeat("x", maxEventsBody) + `"}`, http.StatusRequestEntityTooLarge},
		{"unknown kind", "GET", "/v1/events?kind=exec", "", "", http.StatusBadRequest},
		{"unknown severity", "GET", "/v1/events?min_severity=urgent", "", "", http.StatusBadRequest},
		{"limit too low", "GET", "/v1/events?limit=0", "", "", http.StatusBadRequest},
		{"limit too high", "GET", "/v1/remediations?limit=1001", "", "", http.StatusBadRequest},
		{"short container ID", "GET", "/v1/remediations?container_id=2d1f6c4a9e8b", "", "", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.t = t
			rec := c.do(tt.method, tt.target, tt.contentType, tt.body, false)
			expectStatus(t, rec, tt.want)
		})
	}

	// Every violation of the invalid event is reported with its index.
	c.t = t
	rec := c.do("POST", "/v1/events", "application/json",
		strings.Replace(probeBatch, `"gid": 1000, "comm": "exploit"`, `"gid": 1000, "comm": "`+strings.Repeat("x", 65)+`"`, 1), false)
	expectStatus(t, rec, http.StatusBadRequest)
	p := decodeBody[problem](t, rec)
	if len(p.Errors) != 1 || p.Errors[0].Index != 1 || !strings.Contains(p.Errors[0].Message, "process.comm") {
		t.Errorf("problem = %+v, want one error about process.comm of event 1", p)
	}
}
