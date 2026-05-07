package cache

import (
	"strings"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/packet"
)

type Key struct {
	Name  string // lower-cased, no trailing dot
	Type  uint16
	Class uint16
}

func KeyOf(q *packet.DNSQuestion) Key {
	return Key{
		Name:  strings.ToLower(strings.TrimSuffix(q.Name, ".")),
		Type:  uint16(q.Type),
		Class: uint16(q.Class),
	}
}

type entry struct {
	resp      *packet.DNSPacket
	expiresAt time.Time
}

type Cache struct {
	mu     sync.Mutex
	items  map[Key]entry
	minTTL time.Duration
	maxTTL time.Duration
	negTTL time.Duration
	maxN   int
	now    func() time.Time
}

func New(spec config.CacheSpec) *Cache {
	return &Cache{
		items:  make(map[Key]entry),
		minTTL: spec.MinTTL.Duration(),
		maxTTL: spec.MaxTTL.Duration(),
		negTTL: spec.NegativeTTL.Duration(),
		maxN:   spec.MaxEntries,
		now:    time.Now,
	}
}

func (c *Cache) Get(k Key) (*packet.DNSPacket, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[k]
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.expiresAt) {
		delete(c.items, k)
		return nil, false
	}
	return cloneForReuse(e.resp), true
}

func (c *Cache) Put(k Key, resp *packet.DNSPacket) {
	if resp == nil || resp.Header == nil {
		return
	}
	ttl := c.computeTTL(resp)
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxN > 0 && len(c.items) >= c.maxN {
		c.evictOne(k)
	}
	c.items[k] = entry{
		resp:      cloneForStore(resp),
		expiresAt: c.now().Add(ttl),
	}
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *Cache) computeTTL(resp *packet.DNSPacket) time.Duration {
	if resp.Header.RCode == 3 || len(resp.Answers) == 0 {
		return c.negTTL
	}
	min := uint32(0)
	for _, ans := range resp.Answers {
		t := recordTTL(ans)
		if t == 0 {
			continue
		}
		if min == 0 || t < min {
			min = t
		}
	}
	if min == 0 {
		return c.negTTL
	}
	d := time.Duration(min) * time.Second
	if c.minTTL > 0 && d < c.minTTL {
		d = c.minTTL
	}
	if c.maxTTL > 0 && d > c.maxTTL {
		d = c.maxTTL
	}
	return d
}

func (c *Cache) evictOne(skip Key) {
	for k := range c.items {
		if k == skip {
			continue
		}
		delete(c.items, k)
		return
	}
}

func cloneForStore(p *packet.DNSPacket) *packet.DNSPacket {
	h := *p.Header
	return &packet.DNSPacket{
		Header:      &h,
		Questions:   p.Questions,
		Answers:     p.Answers,
		Authorities: p.Authorities,
		Additionals: p.Additionals,
	}
}

func cloneForReuse(p *packet.DNSPacket) *packet.DNSPacket {
	h := *p.Header
	return &packet.DNSPacket{
		Header:      &h,
		Questions:   p.Questions,
		Answers:     p.Answers,
		Authorities: p.Authorities,
		Additionals: p.Additionals,
	}
}

func recordTTL(r packet.DNSResource) uint32 {
	switch x := r.(type) {
	case *packet.DNSResourceRecordA:
		return x.TTL
	case *packet.DNSResourceRecordAAAA:
		return x.TTL
	case *packet.DNSResourceRecordCNAME:
		return x.TTL
	case *packet.DNSResourceRecordMX:
		return x.TTL
	case *packet.DNSResourceRecordNS:
		return x.TTL
	case *packet.DNSResourceRecordTXT:
		return x.TTL
	case *packet.DNSResourceRecordPTR:
		return x.TTL
	case *packet.DNSResourceRecordSOA:
		return x.TTL
	case *packet.DNSResourceRecordSRV:
		return x.TTL
	case *packet.DNSResourceRecordEDNS:
		return x.TTL
	case *packet.DNSResourceRecordUnknown:
		return x.TTL
	}
	return 0
}
