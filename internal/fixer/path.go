package fixer

import (
	"fmt"
	"strconv"
	"strings"
)

// A Path addresses nodes of a YAML tree, such as
//
//	containers[name=web].securityContext.capabilities.drop
//
// It is written in this grammar:
//
//	path     = segment *( "." segment )
//	segment  = name [ "[" selector "]" ]
//	selector = "*" / index / name "=" value
//	name     = 1*( ALPHA / DIGIT / "_" / "-" )
//	index    = 1*DIGIT
//	value    = 1*( any character but "]" )
//
// Each segment looks a key up in a mapping. Its optional selector then picks
// items of the list stored under that key: "*" every item, an index the item
// at that position and name=value the mappings whose name field is value.
type Path []Segment

// Segment is one step of a Path.
type Segment struct {
	Key string
	Sel Selector
}

// SelectorKind tells how a Segment picks list items.
type SelectorKind int

const (
	SelectNone  SelectorKind = iota // the segment addresses the value under Key
	SelectAll                       // [*]
	SelectIndex                     // [2]
	SelectMatch                     // [name=web]
)

// Selector picks items of a list.
type Selector struct {
	Kind  SelectorKind
	Index int    // for SelectIndex
	Field string // for SelectMatch
	Value string // for SelectMatch
}

// PathError reports a syntax error in a Path.
type PathError struct {
	Path   string
	Offset int // byte offset of the error in Path
	Msg    string
}

func (e *PathError) Error() string {
	return fmt.Sprintf("fixer: invalid path %q at offset %d: %s", e.Path, e.Offset, e.Msg)
}

// ParsePath parses s according to the grammar documented on Path.
func ParsePath(s string) (Path, error) {
	p := pathParser{src: s}
	var path Path
	for {
		seg, err := p.segment()
		if err != nil {
			return nil, err
		}
		path = append(path, seg)
		if p.eof() {
			return path, nil
		}
		if err := p.expect('.'); err != nil {
			return nil, err
		}
	}
}

// String returns the textual form of p, which ParsePath accepts.
func (p Path) String() string {
	var b strings.Builder
	for i, seg := range p {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(seg.Key)
		switch seg.Sel.Kind {
		case SelectAll:
			b.WriteString("[*]")
		case SelectIndex:
			fmt.Fprintf(&b, "[%d]", seg.Sel.Index)
		case SelectMatch:
			fmt.Fprintf(&b, "[%s=%s]", seg.Sel.Field, seg.Sel.Value)
		}
	}
	return b.String()
}

type pathParser struct {
	src string
	pos int
}

func (p *pathParser) eof() bool { return p.pos >= len(p.src) }

func (p *pathParser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.src[p.pos]
}

func (p *pathParser) errorf(format string, args ...any) error {
	return &PathError{Path: p.src, Offset: p.pos, Msg: fmt.Sprintf(format, args...)}
}

func (p *pathParser) expect(c byte) error {
	if p.peek() != c {
		return p.errorf("expected %q", c)
	}
	p.pos++
	return nil
}

func (p *pathParser) segment() (Segment, error) {
	key, err := p.name()
	if err != nil {
		return Segment{}, err
	}
	seg := Segment{Key: key}
	if p.peek() != '[' {
		return seg, nil
	}
	p.pos++
	if seg.Sel, err = p.selector(); err != nil {
		return Segment{}, err
	}
	return seg, p.expect(']')
}

func (p *pathParser) name() (string, error) {
	start := p.pos
	for !p.eof() && isNameByte(p.peek()) {
		p.pos++
	}
	if p.pos == start {
		return "", p.errorf("expected a field name")
	}
	return p.src[start:p.pos], nil
}

func (p *pathParser) selector() (Selector, error) {
	switch c := p.peek(); {
	case c == '*':
		p.pos++
		return Selector{Kind: SelectAll}, nil
	case isDigit(c):
		start := p.pos
		for isDigit(p.peek()) {
			p.pos++
		}
		n, err := strconv.Atoi(p.src[start:p.pos])
		if err != nil {
			p.pos = start
			return Selector{}, p.errorf("index out of range")
		}
		return Selector{Kind: SelectIndex, Index: n}, nil
	}
	field, err := p.name()
	if err != nil {
		return Selector{}, p.errorf(`expected "*", an index or field=value`)
	}
	if err := p.expect('='); err != nil {
		return Selector{}, err
	}
	start := p.pos
	for !p.eof() && p.peek() != ']' {
		p.pos++
	}
	if p.pos == start {
		return Selector{}, p.errorf("expected a value")
	}
	return Selector{Kind: SelectMatch, Field: field, Value: p.src[start:p.pos]}, nil
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isNameByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || isDigit(c) || c == '_' || c == '-'
}
