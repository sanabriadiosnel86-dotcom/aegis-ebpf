package fixer

import (
	"errors"
	"reflect"
	"testing"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		in   string
		want Path
	}{
		{"securityContext", Path{{Key: "securityContext"}}},
		{
			"containers[name=web].securityContext.runAsNonRoot",
			Path{
				{Key: "containers", Sel: Selector{Kind: SelectMatch, Field: "name", Value: "web"}},
				{Key: "securityContext"},
				{Key: "runAsNonRoot"},
			},
		},
		{"containers[*].image", Path{{Key: "containers", Sel: Selector{Kind: SelectAll}}, {Key: "image"}}},
		{"initContainers[12].name", Path{{Key: "initContainers", Sel: Selector{Kind: SelectIndex, Index: 12}}, {Key: "name"}}},
		// Values extend to the closing bracket, dots included.
		{"containers[image=registry.io/nginx:1.27].name", Path{
			{Key: "containers", Sel: Selector{Kind: SelectMatch, Field: "image", Value: "registry.io/nginx:1.27"}},
			{Key: "name"},
		}},
	}
	for _, tt := range tests {
		got, err := ParsePath(tt.in)
		if err != nil {
			t.Errorf("ParsePath(%q): %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParsePath(%q) = %#v, want %#v", tt.in, got, tt.want)
		}
		if s := got.String(); s != tt.in {
			t.Errorf("ParsePath(%q).String() = %q", tt.in, s)
		}
	}
}

func TestParsePathErrors(t *testing.T) {
	tests := []struct {
		in     string
		offset int
	}{
		{"", 0},
		{".a", 0},
		{"a.", 2},
		{"a..b", 2},
		{"a b", 1},
		{"a[", 2},
		{"a[]", 2},
		{"a[*", 3},
		{"a[name]", 6},
		{"a[name=]", 7},
		{"a[name=web", 10},
		{"a[1x]", 3},
		{"a[99999999999999999999]", 2},
		{"a]", 1},
		{"a[*]b", 4},
	}
	for _, tt := range tests {
		_, err := ParsePath(tt.in)
		var perr *PathError
		if !errors.As(err, &perr) {
			t.Errorf("ParsePath(%q) error = %v, want a *PathError", tt.in, err)
			continue
		}
		if perr.Offset != tt.offset {
			t.Errorf("ParsePath(%q) error at offset %d, want %d: %v", tt.in, perr.Offset, tt.offset, err)
		}
	}
}
