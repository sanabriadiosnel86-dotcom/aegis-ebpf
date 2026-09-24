// Package fixer is the syntactic remediation engine of Aegis-eBPF.
//
// A Rule turns a runtime event into a plan: a list of Operations that harden
// the workload running the offending container. Operations address fields
// through a small path language (see Path) relative to the pod spec, so the
// same plan fixes a Pod, a Deployment or a CronJob.
//
// Apply edits the YAML syntax tree of a manifest instead of round-tripping it
// through Go structs: comments, key order and every document that does not
// change survive byte for byte, which keeps GitOps diffs minimal. Each edit is
// also reported as an RFC 6902 JSON Patch operation, ready for
// "kubectl patch --type=json".
package fixer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

var (
	// ErrSyntax reports a manifest that is not valid YAML.
	ErrSyntax = errors.New("fixer: invalid YAML")
	// ErrNoWorkload reports a manifest without any workload document.
	ErrNoWorkload = errors.New("fixer: manifest has no workload")
	// ErrConflict reports a field whose type prevents applying an operation,
	// such as a list where the path expects a mapping.
	ErrConflict = errors.New("fixer: conflicting field")
)

// Op is the kind of an Operation.
type Op string

const (
	// OpSet sets the value at the path, creating missing mappings.
	OpSet Op = "set"
	// OpAdd makes sure the list at the path contains the value, creating the
	// list when missing.
	OpAdd Op = "add"
)

// Operation is a syntactic edit relative to the pod spec of a workload.
type Operation struct {
	Op   Op     `json:"op"`
	Path string `json:"path"`
	// Value is a bool, an integer or a string.
	Value any `json:"value"`
}

// PatchOp is an RFC 6902 JSON Patch operation.
type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// DocumentPatch describes the changes made to one document of a manifest.
type DocumentPatch struct {
	Index      int       `json:"index"`
	APIVersion string    `json:"api_version,omitempty"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name,omitempty"`
	Namespace  string    `json:"namespace,omitempty"`
	Patch      []PatchOp `json:"patch"`
}

// Result is the outcome of Apply.
type Result struct {
	// Manifest is the patched YAML stream, or the input when nothing changed.
	Manifest []byte
	// Documents lists the documents that changed, in stream order.
	Documents []DocumentPatch
}

// podSpecPaths maps the kinds of workload to the location of their pod spec.
var podSpecPaths = map[string][]string{
	"Pod":                   {"spec"},
	"Deployment":            {"spec", "template", "spec"},
	"ReplicaSet":            {"spec", "template", "spec"},
	"ReplicationController": {"spec", "template", "spec"},
	"StatefulSet":           {"spec", "template", "spec"},
	"DaemonSet":             {"spec", "template", "spec"},
	"Job":                   {"spec", "template", "spec"},
	"CronJob":               {"spec", "jobTemplate", "spec", "template", "spec"},
}

// Apply applies ops, in order, to the pod spec of every workload document of
// the YAML stream manifest. Other documents are left untouched. Apply is
// idempotent: applying the same operations to its output changes nothing.
func Apply(manifest []byte, ops []Operation) (*Result, error) {
	plan, err := compile(ops)
	if err != nil {
		return nil, err
	}
	docs, err := decode(manifest)
	if err != nil {
		return nil, err
	}
	res := &Result{Manifest: manifest}
	changed := make([]bool, len(docs))
	workloads := 0
	for i, doc := range docs {
		dp, podSpec, ptr, ok := inspect(doc)
		if !ok {
			continue
		}
		workloads++
		for _, op := range plan {
			if err := op.walk(podSpec, ptr, op.path, &dp.Patch); err != nil {
				return nil, fmt.Errorf("document %d (%s %s): %w", i, dp.Kind, dp.Name, err)
			}
		}
		if len(dp.Patch) > 0 {
			dp.Index = i
			res.Documents = append(res.Documents, dp)
			changed[i] = true
		}
	}
	if workloads == 0 {
		return nil, ErrNoWorkload
	}
	if len(res.Documents) > 0 {
		if res.Manifest, err = render(manifest, docs, changed); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// compiled is an Operation ready to be applied.
type compiled struct {
	Operation
	path Path
	want any // Value as decoded from YAML, for comparisons
}

func compile(ops []Operation) ([]compiled, error) {
	plan := make([]compiled, 0, len(ops))
	for _, op := range ops {
		if op.Op != OpSet && op.Op != OpAdd {
			return nil, fmt.Errorf("fixer: unknown operation %q", op.Op)
		}
		path, err := ParsePath(op.Path)
		if err != nil {
			return nil, err
		}
		if path[len(path)-1].Sel.Kind != SelectNone {
			return nil, fmt.Errorf("fixer: path %q must end with a field name", op.Path)
		}
		switch op.Value.(type) {
		case bool, int, int64, string:
		default:
			return nil, fmt.Errorf("fixer: value of %s %q must be a bool, an integer or a string, not %T", op.Op, op.Path, op.Value)
		}
		var n yaml.Node
		if err := n.Encode(op.Value); err != nil {
			return nil, err
		}
		c := compiled{Operation: op, path: path}
		if err := n.Decode(&c.want); err != nil {
			return nil, err
		}
		plan = append(plan, c)
	}
	return plan, nil
}

// walk applies c at path, relative to the mapping n located at the JSON
// Pointer ptr, and appends the resulting JSON Patch operations to patch.
func (c *compiled) walk(n *yaml.Node, ptr string, path Path, patch *[]PatchOp) error {
	if n.Kind != yaml.MappingNode {
		return conflict(ptr, n, "a mapping")
	}
	seg, rest := path[0], path[1:]
	ptr += "/" + pointerEscaper.Replace(seg.Key)
	v := lookup(n, seg.Key)
	switch {
	case seg.Sel.Kind != SelectNone:
		// Lists of objects, such as containers, are traversed but never
		// created: there is nothing to select in a missing list.
		if v == nil || isNull(v) {
			return nil
		}
		if v.Kind != yaml.SequenceNode {
			return conflict(ptr, v, "a list")
		}
		for i, item := range v.Content {
			if seg.Sel.selects(i, item) {
				if err := c.walk(item, ptr+"/"+strconv.Itoa(i), rest, patch); err != nil {
					return err
				}
			}
		}
		return nil
	case len(rest) == 0:
		return c.edit(n, seg.Key, v, ptr, patch)
	case v == nil || isNull(v):
		if slices.ContainsFunc(rest, func(s Segment) bool { return s.Sel.Kind != SelectNone }) {
			return nil
		}
		node, value := c.leaf()
		for i := len(rest) - 1; i >= 0; i-- {
			node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{keyNode(rest[i].Key), node}}
			value = map[string]any{rest[i].Key: value}
		}
		*patch = append(*patch, put(n, seg.Key, v, node, value, ptr))
		return nil
	default:
		return c.walk(v, ptr, rest, patch)
	}
}

// edit applies c to the value v stored under key in the mapping m. v is nil
// when the key is missing.
func (c *compiled) edit(m *yaml.Node, key string, v *yaml.Node, ptr string, patch *[]PatchOp) error {
	if v == nil || isNull(v) {
		node, value := c.leaf()
		*patch = append(*patch, put(m, key, v, node, value, ptr))
		return nil
	}
	switch c.Op {
	case OpSet:
		if v.Kind != yaml.ScalarNode {
			return conflict(ptr, v, "a scalar")
		}
		if c.holds(v) {
			return nil
		}
		*patch = append(*patch, put(m, key, v, c.scalar(), c.want, ptr))
	case OpAdd:
		if v.Kind != yaml.SequenceNode {
			return conflict(ptr, v, "a list")
		}
		if slices.ContainsFunc(v.Content, c.holds) {
			return nil
		}
		v.Content = append(v.Content, c.scalar())
		*patch = append(*patch, PatchOp{Op: "add", Path: ptr + "/-", Value: c.want})
	}
	return nil
}

// leaf returns what c stores where its target is missing, as a YAML node and
// as a JSON value: the value itself for OpSet, a list holding it for OpAdd.
func (c *compiled) leaf() (*yaml.Node, any) {
	if c.Op == OpAdd {
		return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{c.scalar()}}, []any{c.want}
	}
	return c.scalar(), c.want
}

func (c *compiled) scalar() *yaml.Node {
	n := new(yaml.Node)
	_ = n.Encode(c.want) // cannot fail: compile encoded the same value
	return n
}

// holds reports whether n is a scalar equal to the value of c.
func (c *compiled) holds(n *yaml.Node) bool {
	var have any
	return n.Kind == yaml.ScalarNode && n.Decode(&have) == nil && have == c.want
}

func (s Selector) selects(i int, item *yaml.Node) bool {
	switch s.Kind {
	case SelectAll:
		return true
	case SelectIndex:
		return i == s.Index
	case SelectMatch:
		if item.Kind != yaml.MappingNode {
			return false
		}
		f := lookup(item, s.Field)
		return f != nil && f.Kind == yaml.ScalarNode && f.Value == s.Value
	}
	return false
}

// put stores node under key in the mapping m, in place of old when the key
// exists, and returns the JSON Patch operation that does the same.
func put(m *yaml.Node, key string, old, node *yaml.Node, value any, ptr string) PatchOp {
	if old != nil {
		// Keep the comments attached to the old value.
		old.Kind, old.Style, old.Tag, old.Value, old.Content = node.Kind, node.Style, node.Tag, node.Value, node.Content
		return PatchOp{Op: "replace", Path: ptr, Value: value}
	}
	if len(m.Content) == 0 {
		m.Style &^= yaml.FlowStyle // turn "{}" into a block mapping
	}
	m.Content = append(m.Content, keyNode(key), node)
	return PatchOp{Op: "add", Path: ptr, Value: value}
}

// pointerEscaper escapes a key for use in a JSON Pointer (RFC 6901).
var pointerEscaper = strings.NewReplacer("~", "~0", "/", "~1")

func keyNode(key string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
}

// lookup returns the value stored under key in the mapping m, or nil.
func lookup(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i]; k.Kind == yaml.ScalarNode && k.Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" }

func conflict(ptr string, n *yaml.Node, want string) error {
	have := "a scalar"
	switch n.Kind {
	case yaml.MappingNode:
		have = "a mapping"
	case yaml.SequenceNode:
		have = "a list"
	case yaml.AliasNode:
		have = "an alias"
	}
	return fmt.Errorf("%w: %s (line %d) is %s, want %s", ErrConflict, ptr, n.Line, have, want)
}

// inspect returns the identity, pod spec and pod spec JSON Pointer of doc,
// or false when doc is not a workload.
func inspect(doc *yaml.Node) (dp DocumentPatch, podSpec *yaml.Node, ptr string, ok bool) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return dp, nil, "", false
	}
	root := doc.Content[0]
	dp.APIVersion = scalar(lookup(root, "apiVersion"))
	dp.Kind = scalar(lookup(root, "kind"))
	if meta := lookup(root, "metadata"); meta != nil && meta.Kind == yaml.MappingNode {
		dp.Name = scalar(lookup(meta, "name"))
		dp.Namespace = scalar(lookup(meta, "namespace"))
	}
	keys, ok := podSpecPaths[dp.Kind]
	if !ok {
		return dp, nil, "", false
	}
	podSpec = root
	for _, k := range keys {
		if podSpec = lookup(podSpec, k); podSpec == nil || podSpec.Kind != yaml.MappingNode {
			return dp, nil, "", false
		}
		ptr += "/" + k
	}
	return dp, podSpec, ptr, true
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func decode(manifest []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(manifest))
	var docs []*yaml.Node
	for {
		doc := new(yaml.Node)
		err := dec.Decode(doc)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSyntax, err)
		}
		docs = append(docs, doc)
	}
}

// render re-encodes the changed documents and copies the others verbatim from
// src. When the document boundaries of src cannot be located reliably, it
// re-encodes every document.
func render(src []byte, docs []*yaml.Node, changed []bool) ([]byte, error) {
	lines := bytes.SplitAfter(src, []byte("\n"))
	// Document i spans lines[start[i]:start[i+1]]. Every document but the
	// first begins with its "---" marker, which the decoder reports as the
	// line of the document node.
	start := make([]int, len(docs)+1)
	start[len(docs)] = len(lines)
	verbatim := true
	for i := 1; i < len(docs) && verbatim; i++ {
		start[i] = docs[i].Line - 1
		verbatim = start[i] > start[i-1] && start[i] < len(lines) && isMarker(lines[start[i]])
	}
	var out bytes.Buffer
	for i, doc := range docs {
		switch {
		case !verbatim:
			if i > 0 {
				out.WriteString("---\n")
			}
		case !changed[i]:
			out.Write(bytes.Join(lines[start[i]:start[i+1]], nil))
			continue
		case isMarker(lines[start[i]]):
			out.Write(lines[start[i]])
		}
		b, err := encode(doc)
		if err != nil {
			return nil, err
		}
		out.Write(b)
	}
	return out.Bytes(), nil
}

func isMarker(line []byte) bool { return string(bytes.TrimRight(line, " \t\r\n")) == "---" }

// encode encodes doc in the indentation and list style it was written in.
func encode(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	indent, compact := styleOf(doc)
	enc.SetIndent(indent)
	if compact {
		enc.CompactSeqIndent()
	}
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// styleOf infers the indentation width of doc and whether its block lists
// are indented under their key ("key:\n  - a") or not ("key:\n- a").
func styleOf(doc *yaml.Node) (indent int, compact bool) {
	indent = 2
	var foundIndent, foundList bool
	var visit func(n *yaml.Node)
	visit = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode && n.Style&yaml.FlowStyle == 0 {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if v.Style&yaml.FlowStyle != 0 || len(v.Content) == 0 || v.Line <= k.Line {
					continue
				}
				switch {
				case v.Kind == yaml.MappingNode && !foundIndent:
					if d := v.Column - k.Column; d >= 2 && d <= 8 {
						indent, foundIndent = d, true
					}
				case v.Kind == yaml.SequenceNode && !foundList:
					compact, foundList = v.Column == k.Column, true
				}
			}
		}
		for _, c := range n.Content {
			if !foundIndent || !foundList {
				visit(c)
			}
		}
	}
	visit(doc)
	return indent, compact
}
