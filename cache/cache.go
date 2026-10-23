// Package cache is an LRU response cache for forwarded answers.
package cache

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

// Key identifies a cached response. DO and CD are part of the key because
// they change what an upstream returns (RRSIGs, unvalidated data).
type Key struct {
	Name  string // lower-cased, no trailing dot
	Type  packet.DNSType
	Class packet.DNSClass
	DO    bool
	CD    bool
}

// KeyFor builds the key for a question and the client's DO/CD bits.
func KeyFor(q *packet.DNSQuestion, do, cd bool) Key {
	return Key{
		Name:  strings.ToLower(strings.TrimSuffix(q.Name, ".")),
		Type:  q.Type,
		Class: q.Class,
		DO:    do,
		CD:    cd,
	}
}

// Options bounds cache lifetimes and size.
type Options struct {
	MinTTL      time.Duration // floor for positive answers
	MaxTTL      time.Duration // ceiling for positive answers
	NegativeTTL time.Duration // ceiling for NXDOMAIN/NODATA (RFC 2308)
	MaxEntries  int           // LRU capacity; zero means unbounded
}

type entry struct {
	key       Key
	wire      []byte
	storedAt  time.Time
	expiresAt time.Time
}

// Cache is safe for concurrent use.
type Cache struct {
	opts Options
	now  func() time.Time

	mu    sync.Mutex
	items map[Key]*list.Element
	lru   *list.List // front = most recently used
}

func New(opts Options) *Cache {
	return &Cache{opts: opts, now: time.Now, items: make(map[Key]*list.Element), lru: list.New()}
}

// Get returns a private copy of a cached response with TTLs reduced by the
// time it has spent in the cache.
func (c *Cache) Get(k Key) (*packet.DNSPacket, bool) {
	c.mu.Lock()
	el, ok := c.items[k]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	e := el.Value.(*entry)
	now := c.now()
	if !now.Before(e.expiresAt) {
		c.removeLocked(el)
		c.mu.Unlock()
		return nil, false
	}
	c.lru.MoveToFront(el)
	wire, storedAt := e.wire, e.storedAt
	c.mu.Unlock()

	res, err := packet.FromBytes(wire)
	if err != nil {
		return nil, false
	}
	ageTTLs(res, uint32(now.Sub(storedAt)/time.Second))
	return res, true
}

// Put stores resp if it is cacheable: NOERROR or NXDOMAIN, not truncated,
// with a positive lifetime.
func (c *Cache) Put(k Key, resp *packet.DNSPacket) {
	if resp == nil || resp.Header == nil || resp.Header.TC == 1 {
		return
	}
	ttl := c.lifetime(resp)
	if ttl <= 0 {
		return
	}
	now := c.now()
	e := &entry{key: k, wire: resp.Bytes(), storedAt: now, expiresAt: now.Add(ttl)}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		c.removeLocked(el)
	}
	if c.opts.MaxEntries > 0 && len(c.items) >= c.opts.MaxEntries {
		if oldest := c.lru.Back(); oldest != nil {
			c.removeLocked(oldest)
		}
	}
	c.items[k] = c.lru.PushFront(e)
}

// Len reports the number of entries, including expired ones not yet evicted.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// Flush removes every entry.
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[Key]*list.Element)
	c.lru.Init()
}

func (c *Cache) removeLocked(el *list.Element) {
	delete(c.items, el.Value.(*entry).key)
	c.lru.Remove(el)
}

func (c *Cache) lifetime(resp *packet.DNSPacket) time.Duration {
	switch resp.RCode() {
	case packet.RCodeSuccess:
		if len(resp.Answers) > 0 {
			return c.positiveTTL(resp)
		}
		return c.negativeTTL(resp)
	case packet.RCodeNameError:
		return c.negativeTTL(resp)
	default:
		return 0
	}
}

func (c *Cache) positiveTTL(resp *packet.DNSPacket) time.Duration {
	min := resp.Answers[0].Header().TTL
	for _, r := range resp.Answers[1:] {
		if ttl := r.Header().TTL; ttl < min {
			min = ttl
		}
	}
	d := time.Duration(min) * time.Second
	if d < c.opts.MinTTL {
		d = c.opts.MinTTL
	}
	if c.opts.MaxTTL > 0 && d > c.opts.MaxTTL {
		d = c.opts.MaxTTL
	}
	return d
}

// negativeTTL follows RFC 2308 §5: min(SOA TTL, SOA MINIMUM), capped.
func (c *Cache) negativeTTL(resp *packet.DNSPacket) time.Duration {
	d := c.opts.NegativeTTL
	for _, r := range resp.Authorities {
		soa, ok := r.(*packet.DNSResourceRecordSOA)
		if !ok {
			continue
		}
		ttl := min(soa.TTL, soa.Minimum)
		if soaTTL := time.Duration(ttl) * time.Second; soaTTL < d {
			d = soaTTL
		}
		break
	}
	return d
}

func ageTTLs(p *packet.DNSPacket, elapsed uint32) {
	if elapsed == 0 {
		return
	}
	for _, section := range [][]packet.DNSResource{p.Answers, p.Authorities, p.Additionals} {
		for _, r := range section {
			if r.GetType() == packet.DNSTypeEDNS {
				continue // OPT's TTL field carries flags, not a lifetime
			}
			h := r.Header()
			if elapsed >= h.TTL {
				h.TTL = 0
			} else {
				h.TTL -= elapsed
			}
		}
	}
}
