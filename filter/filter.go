package filter

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

type Action int

const (
	Pass Action = iota
	Block
)

type Filter struct {
	mu        sync.RWMutex
	blockSub  map[string]bool // ||domain^ subdomain match
	allowSub  map[string]bool // @@||domain^ subdomain exception
	important map[string]bool // ||domain^$important — overrides allow
	exact     map[string]bool // bare "domain.tld" — exact-only block
}

func New() *Filter {
	return &Filter{
		blockSub:  make(map[string]bool),
		allowSub:  make(map[string]bool),
		important: make(map[string]bool),
		exact:     make(map[string]bool),
	}
}

func (f *Filter) AddRule(line string) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
		return nil
	}
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return nil
	}
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") {
		log.Printf("filter: skip element-hiding rule %q (not supported)", line)
		return nil
	}
	if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") {
		log.Printf("filter: skip regex rule %q (not supported)", line)
		return nil
	}

	rule, modifiers := splitModifiers(line)
	important := false
	for _, m := range modifiers {
		switch m {
		case "important":
			important = true
		default:
			log.Printf("filter: skip rule %q (modifier $%s not supported)", line, m)
			return nil
		}
	}

	exception := false
	if strings.HasPrefix(rule, "@@") {
		exception = true
		rule = rule[2:]
	}

	if strings.HasPrefix(rule, "||") {
		domain := strings.TrimRight(rule[2:], "^|/")
		domain = strings.ToLower(domain)
		if domain == "" {
			return fmt.Errorf("filter: malformed rule %q", line)
		}
		if strings.ContainsAny(domain, "*?") {
			log.Printf("filter: skip rule %q (wildcard not supported in DNS-only mode)", line)
			return nil
		}
		if !validDomain(domain) {
			return fmt.Errorf("filter: malformed rule %q", line)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if exception {
			f.allowSub[domain] = true
		} else {
			f.blockSub[domain] = true
			if important {
				f.important[domain] = true
			}
		}
		return nil
	}

	if validDomain(strings.ToLower(rule)) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if exception {
			delete(f.exact, strings.ToLower(rule))
			f.allowSub[strings.ToLower(rule)] = true
		} else {
			f.exact[strings.ToLower(rule)] = true
		}
		return nil
	}

	log.Printf("filter: skip rule %q (unsupported syntax)", line)
	return nil
}

func splitModifiers(rule string) (string, []string) {
	idx := strings.LastIndex(rule, "$")
	if idx < 0 {
		return rule, nil
	}
	mods := strings.Split(rule[idx+1:], ",")
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		m = strings.TrimSpace(m)
		if m != "" {
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
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '.' || ch == '-' || ch == '_':
		default:
			return false
		}
	}
	return strings.Contains(s, ".")
}

func (f *Filter) AddListFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open filter list %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if err := f.AddRule(scanner.Text()); err != nil {
			log.Printf("filter: %s:%d: %v", path, lineNo, err)
		}
	}
	return scanner.Err()
}

func (f *Filter) Decide(qname string) Action {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	if qname == "" {
		return Pass
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.exact[qname] {
		if f.allowSub[qname] && !f.important[qname] {
			return Pass
		}
		return Block
	}

	for _, suffix := range suffixes(qname) {
		if f.important[suffix] {
			return Block
		}
	}
	for _, suffix := range suffixes(qname) {
		if f.allowSub[suffix] {
			return Pass
		}
	}
	for _, suffix := range suffixes(qname) {
		if f.blockSub[suffix] {
			return Block
		}
	}
	return Pass
}

func suffixes(name string) []string {
	parts := strings.Split(name, ".")
	out := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}
