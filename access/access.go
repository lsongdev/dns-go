// Package access decides which clients may query the server and who they
// are. It combines network rules (for LANs and routers, where the source
// address is the trust boundary) with client identifiers (for devices that
// roam across networks and reach a public endpoint over DoH or DoT).
package access

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/lsongdev/dns-go/server"
)

// Client is a known device or user.
type Client struct {
	Name string
	// IDs are identifiers the client presents: DoH path "/dns-query/{id}"
	// or DoT/DoH SNI "{id}.<hostname>". Treat them as secrets on public
	// endpoints. Case-insensitive.
	IDs []string
	// Networks identify the client by source address (e.g. a phone's DHCP
	// reservation). Matching a network also grants access.
	Networks []netip.Prefix
}

// Action is what happens to a refused query.
type Action string

const (
	// Refuse answers with RCODE REFUSED.
	Refuse Action = "refuse"
	// Drop sends nothing on UDP (no reflection toward spoofed sources) and
	// falls back to Refuse on connection-oriented transports.
	Drop Action = "drop"
)

// Rules is the full access configuration.
type Rules struct {
	// Allow lists networks that may query without a client identifier.
	// nil means everyone; an empty non-nil slice means no one.
	Allow []netip.Prefix
	// Deny always wins, even over a valid client identifier.
	Deny    []netip.Prefix
	Clients []Client
	// DenyAction defaults to Refuse.
	DenyAction Action
}

// Private networks: loopback, RFC 1918, RFC 6598 (CGNAT), link-local, and
// IPv6 ULA. A sensible Allow for resolvers on a LAN or router.
var Private = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// Request describes who is asking.
type Request struct {
	Addr     netip.Addr
	ClientID string
}

// Decision is the outcome of Check.
type Decision struct {
	Allowed bool
	Action  Action // set when !Allowed
	Client  string // name of the identified client, if any
	Reason  string // why the query was refused
}

// Controller holds the active rules. Check is lock-free; Set swaps rules
// atomically and is safe to call while queries are being served.
type Controller struct {
	state atomic.Pointer[compiled]
}

type compiled struct {
	rules    Rules
	allowAll bool
	byID     map[string]string // lower-cased id -> client name
	networks []namedPrefix     // client networks, most specific first
}

type namedPrefix struct {
	prefix netip.Prefix
	name   string
}

// New returns a Controller enforcing r.
func New(r Rules) (*Controller, error) {
	c := &Controller{}
	if err := c.Set(r); err != nil {
		return nil, err
	}
	return c, nil
}

// Set validates and installs r. On error the current rules stay.
func (c *Controller) Set(r Rules) error {
	if r.DenyAction == "" {
		r.DenyAction = Refuse
	}
	if r.DenyAction != Refuse && r.DenyAction != Drop {
		return fmt.Errorf("access: unknown deny action %q", r.DenyAction)
	}
	state := &compiled{rules: cloneRules(r), allowAll: r.Allow == nil, byID: make(map[string]string)}
	names := make(map[string]bool)
	for i, cl := range r.Clients {
		if cl.Name == "" {
			return fmt.Errorf("access: clients[%d]: name required", i)
		}
		if names[cl.Name] {
			return fmt.Errorf("access: duplicate client name %q", cl.Name)
		}
		names[cl.Name] = true
		for _, id := range cl.IDs {
			if !server.ValidClientID(id) {
				return fmt.Errorf("access: client %q: invalid id %q (use letters, digits, hyphens; at most 63)", cl.Name, id)
			}
			key := strings.ToLower(id)
			if other, dup := state.byID[key]; dup {
				return fmt.Errorf("access: id %q used by both %q and %q", id, other, cl.Name)
			}
			state.byID[key] = cl.Name
		}
		for _, p := range cl.Networks {
			state.networks = append(state.networks, namedPrefix{p.Masked(), cl.Name})
		}
	}
	sort.SliceStable(state.networks, func(i, j int) bool {
		return state.networks[i].prefix.Bits() > state.networks[j].prefix.Bits()
	})
	c.state.Store(state)
	return nil
}

// Rules returns a copy of the active rules.
func (c *Controller) Rules() Rules {
	return cloneRules(c.state.Load().rules)
}

// Check decides one query. Order: deny networks, then a presented client
// ID (which must be known), then client networks, then allow networks.
func (c *Controller) Check(req Request) Decision {
	s := c.state.Load()
	addr := req.Addr.Unmap()
	refuse := func(reason string) Decision {
		return Decision{Action: s.rules.DenyAction, Reason: reason}
	}
	if contains(s.rules.Deny, addr) {
		return refuse("denied network")
	}
	if req.ClientID != "" {
		name, ok := s.byID[strings.ToLower(req.ClientID)]
		if !ok {
			return refuse("unknown client id")
		}
		return Decision{Allowed: true, Client: name}
	}
	for _, n := range s.networks {
		if n.prefix.Contains(addr) {
			return Decision{Allowed: true, Client: n.name}
		}
	}
	if s.allowAll || contains(s.rules.Allow, addr) {
		return Decision{Allowed: true}
	}
	return refuse("network not allowed")
}

// AllowsEveryone reports whether any address may query without an ID.
func (c *Controller) AllowsEveryone() bool {
	s := c.state.Load()
	if s.allowAll {
		return true
	}
	for _, p := range s.rules.Allow {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func cloneRules(r Rules) Rules {
	out := r
	if r.Allow != nil {
		out.Allow = append([]netip.Prefix{}, r.Allow...)
	}
	out.Deny = append([]netip.Prefix(nil), r.Deny...)
	out.Clients = make([]Client, len(r.Clients))
	for i, cl := range r.Clients {
		out.Clients[i] = Client{
			Name:     cl.Name,
			IDs:      append([]string(nil), cl.IDs...),
			Networks: append([]netip.Prefix(nil), cl.Networks...),
		}
	}
	return out
}

// ParseNetworks parses CIDRs, bare addresses (as single-host prefixes), and
// the keyword "private" (expands to Private).
func ParseNetworks(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range entries {
		e = strings.TrimSpace(e)
		switch {
		case e == "private":
			out = append(out, Private...)
		case strings.Contains(e, "/"):
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("access: invalid network %q", e)
			}
			out = append(out, p.Masked())
		default:
			a, err := netip.ParseAddr(e)
			if err != nil {
				return nil, fmt.Errorf("access: invalid network %q", e)
			}
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, nil
}
