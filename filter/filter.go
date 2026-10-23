// Package filter decides whether a query name is blocked, using AdBlock-style
// DNS rules (the subset AdGuard DNS filters use for domains):
//
//	||example.com^            block example.com and its subdomains
//	||example.com^$important  block, overriding allow rules
//	@@||example.com^          allow example.com and its subdomains
//	example.com               block exactly example.com
//
// Rules are grouped into named lists so they can be replaced, removed, and
// reported on independently. hosts-file syntax ("0.0.0.0 name") is
// deliberately not a filter format: local name→address data belongs in zones.
package filter

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Action is the outcome of matching a name.
type Action uint8

const (
	Pass  Action = iota // no rule matched
	Block               // a block rule matched
	Allow               // an allow (exception) rule matched
)

func (a Action) String() string {
	switch a {
	case Block:
		return "block"
	case Allow:
		return "allow"
	default:
		return "pass"
	}
}

// Kind says how a list's plain rules are interpreted.
type Kind string

const (
	// BlockList rules block unless prefixed with "@@".
	BlockList Kind = "block"
	// AllowList rules are all exceptions, with or without "@@".
	AllowList Kind = "allow"
)

// List is a named set of rules.
type List struct {
	Name  string
	Kind  Kind
	Rules []string
}

// ListInfo summarizes an installed list.
type ListInfo struct {
	Name    string
	Kind    Kind
	Rules   int // rules installed
	Skipped int // comments excluded; lines with unsupported syntax
}

// Match explains a decision: which rule, from which list, produced it.
type Match struct {
	Action Action
	Rule   string
	List   string
}

// Rule is one parsed filter rule.
type Rule struct {
	Domain    string
	Allow     bool
	Important bool
	Exact     bool // plain "domain" rule: exactly this name, no subdomains
	Text      string
}

// ErrUnsupported marks syntax this DNS filter recognizes but cannot apply
// (cosmetic rules, regexes, wildcards, request modifiers).
type ErrUnsupported struct{ Line, Reason string }

func (e *ErrUnsupported) Error() string { return fmt.Sprintf("filter: %s: %q", e.Reason, e.Line) }

// ParseRule parses one line. It returns (nil, nil) for blank lines and
// comments, *ErrUnsupported for valid-but-unsupported syntax, and another
// error for malformed rules.
func ParseRule(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") ||
		(strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")) {
		return nil, nil
	}
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") {
		return nil, &ErrUnsupported{line, "element hiding rules are not supported"}
	}
	if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") && len(line) > 1 {
		return nil, &ErrUnsupported{line, "regex rules are not supported"}
	}

	text := line
	rule := &Rule{Text: text}
	body, modifiers := splitModifiers(line)
	for _, m := range modifiers {
		if m != "important" {
			return nil, &ErrUnsupported{text, "modifier $" + m + " is not supported"}
		}
		rule.Important = true
	}
	if strings.HasPrefix(body, "@@") {
		rule.Allow = true
		body = body[2:]
	}
	if strings.HasPrefix(body, "||") {
		body = strings.TrimRight(body[2:], "^|/")
	} else {
		rule.Exact = true
	}
	domain := strings.ToLower(strings.TrimSuffix(body, "."))
	if strings.ContainsAny(domain, "*?") {
		return nil, &ErrUnsupported{text, "wildcards are not supported"}
	}
	if !validDomain(domain) {
		return nil, fmt.Errorf("filter: malformed rule %q", text)
	}
	rule.Domain = domain
	return rule, nil
}

func splitModifiers(rule string) (string, []string) {
	idx := strings.LastIndex(rule, "$")
	if idx < 0 {
		return rule, nil
	}
	var out []string
	for _, m := range strings.Split(rule[idx+1:], ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return rule[:idx], out
}

func validDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, ch := range s {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '.', ch == '-', ch == '_':
		default:
			return false
		}
	}
	return strings.Contains(s, ".")
}

// Filter holds named rule lists. Changes recompile a merged snapshot that
// Match reads without locking.
type Filter struct {
	mu       sync.Mutex
	lists    map[string]*compiledList
	snapshot atomic.Pointer[ruleSet]
}

type compiledList struct {
	info  ListInfo
	rules []*Rule
}

type ruleRef struct {
	list string
	rule string
}

type ruleSet struct {
	important map[string]ruleRef // suffix block that beats allow
	allow     map[string]ruleRef // suffix allow
	block     map[string]ruleRef // suffix block
	exact     map[string]ruleRef // exact-name block
}

func New() *Filter {
	f := &Filter{lists: make(map[string]*compiledList)}
	f.snapshot.Store(&ruleSet{})
	return f
}

// SetList installs or replaces a list. Unsupported or malformed lines are
// skipped and counted; use ParseRule to validate rules individually.
func (f *Filter) SetList(l List) ListInfo {
	c := compileList(l.Name, l.Kind, func(yield func(string) bool) {
		for _, line := range l.Rules {
			if !yield(line) {
				return
			}
		}
	})
	f.install(c)
	return c.info
}

// SetListFrom installs a list read line by line from r.
func (f *Filter) SetListFrom(name string, kind Kind, r io.Reader) (ListInfo, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	c := compileList(name, kind, func(yield func(string) bool) {
		for scanner.Scan() {
			if !yield(scanner.Text()) {
				return
			}
		}
	})
	if err := scanner.Err(); err != nil {
		return ListInfo{}, fmt.Errorf("filter: read list %q: %w", name, err)
	}
	f.install(c)
	return c.info, nil
}

func compileList(name string, kind Kind, lines func(func(string) bool)) *compiledList {
	if kind == "" {
		kind = BlockList
	}
	c := &compiledList{info: ListInfo{Name: name, Kind: kind}}
	lines(func(line string) bool {
		rule, err := ParseRule(line)
		if err != nil {
			c.info.Skipped++
			return true
		}
		if rule == nil {
			return true
		}
		if kind == AllowList {
			rule.Allow = true
		}
		c.rules = append(c.rules, rule)
		return true
	})
	c.info.Rules = len(c.rules)
	return c
}

// RemoveList deletes a list, reporting whether it existed.
func (f *Filter) RemoveList(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.lists[name]; !ok {
		return false
	}
	delete(f.lists, name)
	f.rebuild()
	return true
}

// Lists reports installed lists ordered by name.
func (f *Filter) Lists() []ListInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ListInfo, 0, len(f.lists))
	for _, l := range f.lists {
		out = append(out, l.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (f *Filter) install(c *compiledList) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists[c.info.Name] = c
	f.rebuild()
}

// rebuild merges all lists; must be called with f.mu held. Lists are merged
// in name order so the reported rule is deterministic when several match.
func (f *Filter) rebuild() {
	names := make([]string, 0, len(f.lists))
	total := 0
	for name, l := range f.lists {
		names = append(names, name)
		total += len(l.rules)
	}
	sort.Strings(names)
	set := &ruleSet{
		important: make(map[string]ruleRef),
		allow:     make(map[string]ruleRef),
		block:     make(map[string]ruleRef, total),
		exact:     make(map[string]ruleRef),
	}
	for _, name := range names {
		for _, r := range f.lists[name].rules {
			ref := ruleRef{list: name, rule: r.Text}
			var target map[string]ruleRef
			switch {
			case r.Allow:
				target = set.allow
			case r.Important:
				target = set.important
			case r.Exact:
				target = set.exact
			default:
				target = set.block
			}
			if _, ok := target[r.Domain]; !ok {
				target[r.Domain] = ref
			}
		}
	}
	f.snapshot.Store(set)
}

// Match decides qname. Precedence: $important blocks, then allow rules, then
// block rules; within each class any matching suffix applies.
func (f *Filter) Match(qname string) Match {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	if qname == "" {
		return Match{}
	}
	set := f.snapshot.Load()
	if ref, ok := lookupSuffix(set.important, qname); ok {
		return Match{Action: Block, Rule: ref.rule, List: ref.list}
	}
	if ref, ok := lookupSuffix(set.allow, qname); ok {
		return Match{Action: Allow, Rule: ref.rule, List: ref.list}
	}
	if ref, ok := set.exact[qname]; ok {
		return Match{Action: Block, Rule: ref.rule, List: ref.list}
	}
	if ref, ok := lookupSuffix(set.block, qname); ok {
		return Match{Action: Block, Rule: ref.rule, List: ref.list}
	}
	return Match{}
}

// lookupSuffix checks name and each parent domain, most specific first.
func lookupSuffix(m map[string]ruleRef, name string) (ruleRef, bool) {
	if len(m) == 0 {
		return ruleRef{}, false
	}
	for {
		if ref, ok := m[name]; ok {
			return ref, true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return ruleRef{}, false
		}
		name = name[dot+1:]
	}
}
