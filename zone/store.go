package zone

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lsongdev/dns-go/packet"
)

// Store holds the zones a server answers from. Writers (Put, Delete,
// Replace) compile the changed zone off to the side and atomically publish a
// new snapshot, so Lookup never blocks and never sees a half-applied change.
// Zones are copied on the way in and out; callers may reuse their values.
type Store struct {
	authoritative bool

	mu       sync.Mutex // serializes writers
	sources  map[string]*Zone
	compiled map[string]*compiledZone
	snapshot atomic.Pointer[snapshot]
}

// StoreOptions configures validation policy.
type StoreOptions struct {
	// Authoritative requires every zone to be Static with exactly one apex
	// SOA and at least one apex NS, as a public name server must serve.
	Authoritative bool
}

func NewStore(opts StoreOptions) *Store {
	s := &Store{
		authoritative: opts.Authoritative,
		sources:       make(map[string]*Zone),
		compiled:      make(map[string]*compiledZone),
	}
	s.snapshot.Store(&snapshot{root: newTrieNode()})
	return s
}

// Put adds or replaces the zone with z's origin.
func (s *Store) Put(z *Zone) error {
	src, c, err := s.compile(z)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources[c.origin] = src
	s.compiled[c.origin] = c
	s.publish()
	return nil
}

// Delete removes a zone, reporting whether it existed.
func (s *Store) Delete(origin string) bool {
	origin = CanonicalName(origin)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sources[origin]; !ok {
		return false
	}
	delete(s.sources, origin)
	delete(s.compiled, origin)
	s.publish()
	return true
}

// Replace swaps the full zone set. On error nothing changes.
func (s *Store) Replace(zones []*Zone) error {
	sources := make(map[string]*Zone, len(zones))
	compiled := make(map[string]*compiledZone, len(zones))
	for i, z := range zones {
		src, c, err := s.compile(z)
		if err != nil {
			return fmt.Errorf("zones[%d]: %w", i, err)
		}
		if _, dup := compiled[c.origin]; dup {
			return fmt.Errorf("zones[%d]: duplicate zone %q", i, displayName(c.origin))
		}
		sources[c.origin] = src
		compiled[c.origin] = c
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = sources
	s.compiled = compiled
	s.publish()
	return nil
}

// Get returns a copy of the zone with the given origin.
func (s *Store) Get(origin string) (*Zone, bool) {
	s.mu.Lock()
	src, ok := s.sources[CanonicalName(origin)]
	s.mu.Unlock()
	if !ok {
		return nil, false
	}
	return cloneZone(src), true
}

// List returns copies of all zones ordered by origin.
func (s *Store) List() []*Zone {
	s.mu.Lock()
	out := make([]*Zone, 0, len(s.sources))
	for _, src := range s.sources {
		out = append(out, src)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Origin < out[j].Origin })
	for i, z := range out {
		out[i] = cloneZone(z)
	}
	return out
}

func (s *Store) compile(z *Zone) (*Zone, *compiledZone, error) {
	if z == nil {
		return nil, nil, fmt.Errorf("zone: nil zone")
	}
	src := cloneZone(z)
	src.Origin = CanonicalName(src.Origin)
	if src.Kind == "" {
		src.Kind = Static
	}
	if src.Kind != Static && src.Kind != Transparent {
		return nil, nil, fmt.Errorf("zone %q: unknown kind %q", displayName(src.Origin), src.Kind)
	}
	c, err := compileZone(src)
	if err != nil {
		return nil, nil, fmt.Errorf("zone %q: %w", displayName(src.Origin), err)
	}
	if s.authoritative {
		if err := c.validateAuthoritative(); err != nil {
			return nil, nil, fmt.Errorf("zone %q: %w", displayName(src.Origin), err)
		}
	}
	return src, c, nil
}

// publish must be called with s.mu held.
func (s *Store) publish() {
	root := newTrieNode()
	for _, c := range s.compiled {
		root.insert(c)
	}
	s.snapshot.Store(&snapshot{root: root})
}

func cloneZone(z *Zone) *Zone {
	out := *z
	out.Records = make([]packet.DNSResource, 0, len(z.Records))
	for _, r := range z.Records {
		if c, err := packet.CloneResource(r); err == nil {
			out.Records = append(out.Records, c)
		}
	}
	return &out
}

// Result is the outcome of a Lookup.
type Result struct {
	// Found is false when no zone covers the name, or a transparent zone has
	// no data for it; the caller should continue resolving elsewhere.
	Found         bool
	Authoritative bool
	RCode         uint16
	Answers       []packet.DNSResource
	Authorities   []packet.DNSResource
	Additionals   []packet.DNSResource
}

// Lookup answers a question from the current snapshot. Returned records are
// shared with the store and must not be modified.
func (s *Store) Lookup(qname string, qtype packet.DNSType, qclass packet.DNSClass) Result {
	if qclass != packet.DNSClassIN && qclass != packet.DNSClassAny {
		return Result{}
	}
	qname = CanonicalName(qname)
	z := s.snapshot.Load().root.match(qname)
	if z == nil {
		return Result{}
	}
	if z.kind == Transparent {
		return z.lookupTransparent(qname, qtype)
	}
	return z.lookupStatic(qname, qtype)
}

func (z *compiledZone) lookupStatic(qname string, qtype packet.DNSType) Result {
	if cut, ns := z.findDelegation(qname); cut != "" && !(qname == cut && qtype == packet.DNSTypeDS) {
		return Result{Found: true, RCode: packet.RCodeSuccess, Authorities: ns, Additionals: z.glueFor(ns)}
	}
	result := Result{Found: true, Authoritative: true, RCode: packet.RCodeSuccess}
	if owner, ok := z.owners[qname]; ok {
		result.Answers = z.answerOwner(qname, owner, qtype)
	} else if _, ok := z.names[qname]; ok {
		// empty non-terminal: NODATA
	} else if wildcard := z.findWildcard(qname); wildcard != "" {
		result.Answers = z.answerWildcard(qname, wildcard, qtype)
	} else {
		result.RCode = packet.RCodeNameError
	}
	if len(result.Answers) == 0 {
		result.Authorities = z.soa
	}
	return result
}

func (z *compiledZone) lookupTransparent(qname string, qtype packet.DNSType) Result {
	result := Result{Found: true, Authoritative: true, RCode: packet.RCodeSuccess}
	if owner, ok := z.owners[qname]; ok {
		result.Answers = z.answerOwner(qname, owner, qtype)
	} else if _, ok := z.names[qname]; ok {
		return Result{}
	} else if wildcard := z.findWildcard(qname); wildcard != "" {
		result.Answers = z.answerWildcard(qname, wildcard, qtype)
	} else {
		return Result{}
	}
	if len(result.Answers) == 0 {
		result.Authorities = z.soa
	}
	return result
}

type snapshot struct {
	root *trieNode
}

type trieNode struct {
	children map[string]*trieNode
	zone     *compiledZone
}

func newTrieNode() *trieNode { return &trieNode{children: make(map[string]*trieNode)} }

func (n *trieNode) insert(z *compiledZone) {
	node := n
	for _, label := range reversedLabels(z.origin) {
		child := node.children[label]
		if child == nil {
			child = newTrieNode()
			node.children[label] = child
		}
		node = child
	}
	node.zone = z
}

// match returns the closest enclosing zone of name.
func (n *trieNode) match(name string) *compiledZone {
	node := n
	best := node.zone // root zone, if any
	for _, label := range reversedLabels(name) {
		node = node.children[label]
		if node == nil {
			break
		}
		if node.zone != nil {
			best = node.zone
		}
	}
	return best
}

func reversedLabels(name string) []string {
	if name == "" {
		return nil
	}
	labels := strings.Split(name, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels
}

type compiledZone struct {
	origin string
	kind   Kind
	owners map[string]map[packet.DNSType][]packet.DNSResource
	names  map[string]struct{}                                // owners plus their ancestors (empty non-terminals)
	sigs   map[string]map[packet.DNSType][]packet.DNSResource // RRSIGs by owner and covered type
	soa    []packet.DNSResource                               // apex SOA plus its signatures
}

func compileZone(src *Zone) (*compiledZone, error) {
	z := &compiledZone{
		origin: src.Origin,
		kind:   src.Kind,
		owners: make(map[string]map[packet.DNSType][]packet.DNSResource),
		names:  map[string]struct{}{src.Origin: {}},
		sigs:   make(map[string]map[packet.DNSType][]packet.DNSResource),
	}
	for _, record := range src.Records {
		h := record.Header()
		name := CanonicalName(h.Name)
		if !z.contains(name) {
			return nil, fmt.Errorf("record owner %q is outside the zone", h.Name)
		}
		if record.GetType() == packet.DNSTypeEDNS {
			return nil, fmt.Errorf("OPT record is not valid zone data")
		}
		record = withName(record, name)
		if z.owners[name] == nil {
			z.owners[name] = make(map[packet.DNSType][]packet.DNSResource)
		}
		z.owners[name][record.GetType()] = append(z.owners[name][record.GetType()], record)
		if sig, ok := record.(*packet.DNSResourceRecordRRSIG); ok {
			if z.sigs[name] == nil {
				z.sigs[name] = make(map[packet.DNSType][]packet.DNSResource)
			}
			z.sigs[name][sig.TypeCovered] = append(z.sigs[name][sig.TypeCovered], record)
		}
		z.addNameAndAncestors(name)
	}
	z.soa = z.rrset(z.origin, packet.DNSTypeSOA)
	for name, owner := range z.owners {
		cnames := owner[packet.DNSTypeCNAME]
		if len(cnames) > 1 {
			return nil, fmt.Errorf("owner %q has multiple CNAME records", name)
		}
		if len(cnames) == 1 && len(owner) > 1 {
			return nil, fmt.Errorf("owner %q has CNAME and other record types", name)
		}
		if len(cnames) == 1 && name == z.origin && z.kind == Static {
			return nil, fmt.Errorf("zone apex cannot be a CNAME")
		}
		if soa := owner[packet.DNSTypeSOA]; len(soa) > 0 {
			if name != z.origin {
				return nil, fmt.Errorf("SOA owner %q must be the zone apex", name)
			}
			if len(soa) > 1 {
				return nil, fmt.Errorf("multiple SOA records")
			}
		}
	}
	if err := z.validateCNAMECycles(); err != nil {
		return nil, err
	}
	return z, nil
}

func (z *compiledZone) validateAuthoritative() error {
	if z.kind != Static {
		return fmt.Errorf("authoritative zones must be %s", Static)
	}
	apex := z.owners[z.origin]
	if len(apex[packet.DNSTypeSOA]) != 1 {
		return fmt.Errorf("requires exactly one apex SOA")
	}
	if len(apex[packet.DNSTypeNS]) == 0 {
		return fmt.Errorf("requires at least one apex NS")
	}
	return nil
}

func (z *compiledZone) contains(name string) bool {
	return z.origin == "" || name == z.origin || strings.HasSuffix(name, "."+z.origin)
}

func (z *compiledZone) validateCNAMECycles() error {
	for start, owner := range z.owners {
		if len(owner[packet.DNSTypeCNAME]) == 0 {
			continue
		}
		seen := map[string]bool{start: true}
		current := start
		for {
			cnames := z.owners[current][packet.DNSTypeCNAME]
			if len(cnames) == 0 {
				break
			}
			target := z.resolveTarget(cnames[0].(*packet.DNSResourceRecordCNAME).Domain)
			if seen[target] {
				return fmt.Errorf("CNAME cycle involving %q", target)
			}
			seen[target] = true
			current = target
		}
	}
	return nil
}

func (z *compiledZone) addNameAndAncestors(name string) {
	for current := name; ; current = parentName(current) {
		z.names[current] = struct{}{}
		if current == z.origin || current == "" {
			return
		}
	}
}

// rrset returns the records of one type at name together with the RRSIGs
// covering them; the engine strips signatures for clients without DO.
func (z *compiledZone) rrset(name string, rtype packet.DNSType) []packet.DNSResource {
	records := z.owners[name][rtype]
	sigs := z.sigs[name][rtype]
	if len(records) == 0 || len(sigs) == 0 {
		return records
	}
	return append(append(make([]packet.DNSResource, 0, len(records)+len(sigs)), records...), sigs...)
}

func (z *compiledZone) answerOwner(name string, owner map[packet.DNSType][]packet.DNSResource, qtype packet.DNSType) []packet.DNSResource {
	if qtype == packet.DNSTypeAny {
		types := make([]int, 0, len(owner))
		for rtype := range owner {
			types = append(types, int(rtype))
		}
		sort.Ints(types)
		var out []packet.DNSResource
		for _, value := range types {
			out = append(out, owner[packet.DNSType(value)]...)
		}
		return out
	}
	if len(owner[qtype]) > 0 {
		return z.rrset(name, qtype)
	}
	if qtype != packet.DNSTypeCNAME && len(owner[packet.DNSTypeCNAME]) > 0 {
		return z.followCNAME(name, qtype)
	}
	return nil
}

// followCNAME expands the CNAME chain starting at name inside the zone. A
// chain that leaves the zone ends with its last CNAME record (signatures are
// placed before each CNAME), so the caller can resolve the target.
func (z *compiledZone) followCNAME(name string, qtype packet.DNSType) []packet.DNSResource {
	var out []packet.DNSResource
	visited := make(map[string]bool)
	for depth := 0; depth < 8; depth++ {
		cnames := z.owners[name][packet.DNSTypeCNAME]
		if len(cnames) == 0 || visited[name] {
			break
		}
		visited[name] = true
		out = append(out, z.sigs[name][packet.DNSTypeCNAME]...)
		out = append(out, cnames...)
		name = z.resolveTarget(cnames[0].(*packet.DNSResourceRecordCNAME).Domain)
		if len(z.owners[name][qtype]) > 0 {
			return append(out, z.rrset(name, qtype)...)
		}
	}
	return out
}

// resolveTarget canonicalizes an RDATA name. Record names are absolute
// (the zone-file parser qualifies relative names); the trailing dot is optional.
func (z *compiledZone) resolveTarget(target string) string {
	return CanonicalName(target)
}

// findWildcard returns the wildcard owner at the closest encloser of name,
// or "" when there is none.
func (z *compiledZone) findWildcard(name string) string {
	for candidate := parentName(name); ; candidate = parentName(candidate) {
		if _, exists := z.names[candidate]; exists {
			wildcard := joinName("*", candidate)
			if z.owners[wildcard] == nil {
				return ""
			}
			return wildcard
		}
		if candidate == z.origin || candidate == "" {
			return ""
		}
	}
}

// answerWildcard synthesizes records from the wildcard owner, renaming the
// records owned by the wildcard itself to qname (RFC 4592).
func (z *compiledZone) answerWildcard(qname, wildcard string, qtype packet.DNSType) []packet.DNSResource {
	records := z.answerOwner(wildcard, z.owners[wildcard], qtype)
	out := make([]packet.DNSResource, 0, len(records))
	for _, record := range records {
		if CanonicalName(record.Header().Name) == wildcard {
			record = withName(record, qname)
		}
		out = append(out, record)
	}
	return out
}

func (z *compiledZone) findDelegation(name string) (string, []packet.DNSResource) {
	for current := name; current != "" && current != z.origin; current = parentName(current) {
		if ns := z.owners[current][packet.DNSTypeNS]; len(ns) > 0 {
			return current, ns
		}
	}
	return "", nil
}

func (z *compiledZone) glueFor(ns []packet.DNSResource) []packet.DNSResource {
	var glue []packet.DNSResource
	for _, record := range ns {
		target := z.resolveTarget(record.(*packet.DNSResourceRecordNS).NameServer)
		if !z.contains(target) {
			continue
		}
		for _, rtype := range []packet.DNSType{packet.DNSTypeA, packet.DNSTypeAAAA} {
			glue = append(glue, z.owners[target][rtype]...)
		}
	}
	return glue
}

// CanonicalName lower-cases name and strips trailing dots; the root is "".
func CanonicalName(name string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(name), "."))
}

func displayName(name string) string {
	if name == "" {
		return "."
	}
	return name
}

func joinName(label, parent string) string {
	if parent == "" {
		return label
	}
	return label + "." + parent
}

func parentName(name string) string {
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		return name[dot+1:]
	}
	return ""
}

func withName(record packet.DNSResource, name string) packet.DNSResource {
	clone, err := packet.CloneResource(record)
	if err != nil {
		return record
	}
	clone.Header().Name = name
	return clone
}
