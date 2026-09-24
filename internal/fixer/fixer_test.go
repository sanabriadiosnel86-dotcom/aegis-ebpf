package fixer

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
)

// hardening is the plan of rule AEG-002 for the container "web".
var hardening = []Operation{
	{Op: OpSet, Path: "containers[name=web].securityContext.allowPrivilegeEscalation", Value: false},
	{Op: OpAdd, Path: "containers[name=web].securityContext.capabilities.drop", Value: "ALL"},
}

func TestApplyPreservesSyntax(t *testing.T) {
	const in = `# Frontend of the shop.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop # owned by team-a
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: web
        image: nginx:1.27 # pinned
        ports:
        - containerPort: 80
      - name: sidecar
        image: envoy:1.31
`
	const want = `# Frontend of the shop.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop # owned by team-a
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: web
        image: nginx:1.27 # pinned
        ports:
        - containerPort: 80
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
      - name: sidecar
        image: envoy:1.31
`
	res := mustApply(t, in, hardening)
	if got := string(res.Manifest); got != want {
		t.Errorf("patched manifest:\n%s\nwant:\n%s", got, want)
	}
	wantDocs := []DocumentPatch{{
		Index: 0, APIVersion: "apps/v1", Kind: "Deployment", Name: "web", Namespace: "shop",
		Patch: []PatchOp{
			{Op: "add", Path: "/spec/template/spec/containers/0/securityContext", Value: map[string]any{"allowPrivilegeEscalation": false}},
			{Op: "add", Path: "/spec/template/spec/containers/0/securityContext/capabilities", Value: map[string]any{"drop": []any{"ALL"}}},
		},
	}}
	if !reflect.DeepEqual(res.Documents, wantDocs) {
		t.Errorf("documents = %#v, want %#v", res.Documents, wantDocs)
	}
	checkJSONPatch(t, in, res)
}

func TestApplyIsIdempotent(t *testing.T) {
	const in = `apiVersion: v1
kind: Pod
metadata:
  name: api
spec:
  containers:
    - name: web
      image: api:2
`
	first := mustApply(t, in, hardening)
	if len(first.Documents) != 1 {
		t.Fatalf("first Apply changed %d documents, want 1", len(first.Documents))
	}
	second := mustApply(t, string(first.Manifest), hardening)
	if len(second.Documents) != 0 {
		t.Errorf("second Apply changed documents: %#v", second.Documents)
	}
	if string(second.Manifest) != string(first.Manifest) {
		t.Errorf("second Apply rewrote the manifest:\n%s", second.Manifest)
	}
	// Indented lists stay indented.
	if !strings.Contains(string(first.Manifest), "\n    - name: web\n") {
		t.Errorf("list style changed:\n%s", first.Manifest)
	}
}

func TestApplyCopiesOtherDocumentsVerbatim(t *testing.T) {
	const service = `---
# Not a workload: never rewritten, whatever its style.
apiVersion: v1
kind: Service
metadata: {name: web}
spec:
    ports:
        - port: 80   # http
`
	const cronJob = `---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: restic:0.17
            securityContext:
              capabilities:
                drop: [NET_RAW]
`
	const configMap = `---
apiVersion: v1
kind: ConfigMap
metadata:
  name:   settings
data:
  mode: "strict"
`
	in := service + cronJob + configMap
	ops := []Operation{{Op: OpAdd, Path: "containers[*].securityContext.capabilities.drop", Value: "ALL"}}
	res := mustApply(t, in, ops)

	const wantCronJob = `---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: restic:0.17
            securityContext:
              capabilities:
                drop: [NET_RAW, ALL]
`
	if got, want := string(res.Manifest), service+wantCronJob+configMap; got != want {
		t.Errorf("patched manifest:\n%s\nwant:\n%s", got, want)
	}
	wantDocs := []DocumentPatch{{
		Index: 1, APIVersion: "batch/v1", Kind: "CronJob", Name: "backup",
		Patch: []PatchOp{{
			Op:    "add",
			Path:  "/spec/jobTemplate/spec/template/spec/containers/0/securityContext/capabilities/drop/-",
			Value: "ALL",
		}},
	}}
	if !reflect.DeepEqual(res.Documents, wantDocs) {
		t.Errorf("documents = %#v, want %#v", res.Documents, wantDocs)
	}
	checkJSONPatch(t, in, res)
}

func TestApplyReplacesExistingValues(t *testing.T) {
	const in = `kind: StatefulSet
metadata:
  name: db
spec:
  template:
    spec:
      containers:
      - name: db
        securityContext:
          # Legacy image, see TICKET-42.
          readOnlyRootFilesystem: false
          runAsNonRoot:
      - name: web
        securityContext:
`
	ops := []Operation{
		{Op: OpSet, Path: "containers[*].securityContext.readOnlyRootFilesystem", Value: true},
		{Op: OpSet, Path: "containers[*].securityContext.runAsNonRoot", Value: true},
	}
	res := mustApply(t, in, ops)
	const want = `kind: StatefulSet
metadata:
  name: db
spec:
  template:
    spec:
      containers:
      - name: db
        securityContext:
          # Legacy image, see TICKET-42.
          readOnlyRootFilesystem: true
          runAsNonRoot: true
      - name: web
        securityContext:
          readOnlyRootFilesystem: true
          runAsNonRoot: true
`
	if got := string(res.Manifest); got != want {
		t.Errorf("patched manifest:\n%s\nwant:\n%s", got, want)
	}
	gotOps := make([]string, 0, 4)
	for _, op := range res.Documents[0].Patch {
		gotOps = append(gotOps, op.Op+" "+op.Path)
	}
	wantOps := []string{
		"replace /spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
		"replace /spec/template/spec/containers/1/securityContext",
		"replace /spec/template/spec/containers/0/securityContext/runAsNonRoot",
		"add /spec/template/spec/containers/1/securityContext/runAsNonRoot",
	}
	if !reflect.DeepEqual(gotOps, wantOps) {
		t.Errorf("patch = %q, want %q", gotOps, wantOps)
	}
	checkJSONPatch(t, in, res)
}

func TestApplySkipsUnselectedContainers(t *testing.T) {
	const in = `kind: Pod
spec:
  containers:
  - name: api
`
	res := mustApply(t, in, hardening) // targets the container "web"
	if len(res.Documents) != 0 || string(res.Manifest) != in {
		t.Errorf("Apply changed a pod without the target container: %#v\n%s", res.Documents, res.Manifest)
	}
}

func TestApplyErrors(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		ops      []Operation
		want     error
	}{
		{"invalid YAML", "kind: Pod\nspec: [\n", hardening, ErrSyntax},
		{"no workload", "kind: Service\nspec: {}\n", hardening, ErrNoWorkload},
		{"workload without pod spec", "kind: Deployment\nspec: {}\n", hardening, ErrNoWorkload},
		{"list instead of mapping", "kind: Pod\nspec:\n  containers:\n  - name: web\n    securityContext: []\n", hardening, ErrConflict},
		{"mapping instead of list", "kind: Pod\nspec:\n  containers: {}\n", hardening, ErrConflict},
		{"scalar instead of list", "kind: Pod\nspec:\n  containers:\n  - name: web\n    securityContext:\n      capabilities:\n        drop: ALL\n", hardening, ErrConflict},
		{"mapping instead of scalar", "kind: Pod\nspec:\n  containers:\n  - name: web\n    securityContext:\n      allowPrivilegeEscalation: {}\n", hardening, ErrConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Apply([]byte(tt.manifest), tt.ops)
			if !errors.Is(err, tt.want) {
				t.Errorf("Apply() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestApplyRejectsInvalidOperations(t *testing.T) {
	const pod = "kind: Pod\nspec:\n  containers: []\n"
	for _, op := range []Operation{
		{Op: "delete", Path: "hostNetwork", Value: true},
		{Op: OpSet, Path: "containers[*]", Value: true},
		{Op: OpSet, Path: "containers[", Value: true},
		{Op: OpSet, Path: "hostNetwork", Value: nil},
		{Op: OpAdd, Path: "tolerations", Value: map[string]any{"key": "x"}},
	} {
		if _, err := Apply([]byte(pod), []Operation{op}); err == nil {
			t.Errorf("Apply(%+v) succeeded, want an error", op)
		}
	}
}

func mustApply(t *testing.T, manifest string, ops []Operation) *Result {
	t.Helper()
	res, err := Apply([]byte(manifest), ops)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return res
}

// checkJSONPatch verifies that the JSON Patch of every changed document turns
// the original document into the patched one.
func checkJSONPatch(t *testing.T, original string, res *Result) {
	t.Helper()
	before, after := documentsJSON(t, original), documentsJSON(t, string(res.Manifest))
	if len(before) != len(after) {
		t.Fatalf("patched manifest has %d documents, want %d", len(after), len(before))
	}
	for _, dp := range res.Documents {
		raw, err := json.Marshal(dp.Patch)
		if err != nil {
			t.Fatal(err)
		}
		patch, err := jsonpatch.DecodePatch(raw)
		if err != nil {
			t.Fatalf("document %d: invalid JSON Patch %s: %v", dp.Index, raw, err)
		}
		got, err := patch.Apply(before[dp.Index])
		if err != nil {
			t.Fatalf("document %d: applying %s: %v", dp.Index, raw, err)
		}
		if !jsonpatch.Equal(got, after[dp.Index]) {
			t.Errorf("document %d: JSON Patch yields\n%s\nwant\n%s", dp.Index, got, after[dp.Index])
		}
	}
}

func documentsJSON(t *testing.T, stream string) [][]byte {
	t.Helper()
	docs, err := decode([]byte(stream))
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, len(docs))
	for i, doc := range docs {
		var v any
		if err := doc.Decode(&v); err != nil {
			t.Fatal(err)
		}
		if out[i], err = json.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	return out
}
