package cache

import (
	"testing"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time          { return f.t }
func (f *fakeClock) Advance(d time.Duration) { f.t = f.t.Add(d) }

func newTestCache(opts Options) (*Cache, *fakeClock) {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := New(opts)
	c.now = clock.Now
	return c, clock
}

func defaultOpts() Options {
	return Options{MaxTTL: time.Hour, NegativeTTL: 5 * time.Minute, MaxEntries: 100}
}

func newAResponse(name string, ttl uint32) *packet.DNSPacket {
	p := &packet.DNSPacket{Header: &packet.DNSHeader{QR: packet.DNSResponse}}
	p.AddQuestion(&packet.DNSQuestion{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN})
	p.AddAnswer(&packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: ttl},
		Address:           "1.2.3.4",
	})
	return p
}

func newNegative(name string, rcode uint8, soaTTL, soaMin uint32) *packet.DNSPacket {
	p := &packet.DNSPacket{Header: &packet.DNSHeader{QR: packet.DNSResponse, RCode: rcode}}
	p.AddQuestion(&packet.DNSQuestion{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN})
	if soaTTL > 0 {
		p.AddAuthority(&packet.DNSResourceRecordSOA{
			DNSResourceRecord: packet.DNSResourceRecord{Name: "example.com", Type: packet.DNSTypeSOA, Class: packet.DNSClassIN, TTL: soaTTL},
			MName:             "ns.example.com", RName: "admin.example.com", Minimum: soaMin,
		})
	}
	return p
}

func keyA(name string) Key {
	return KeyFor(&packet.DNSQuestion{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN}, false, false)
}

func TestHitMissAndExpiry(t *testing.T) {
	c, clock := newTestCache(defaultOpts())
	if _, ok := c.Get(keyA("a.com")); ok {
		t.Fatal("empty cache hit")
	}
	c.Put(keyA("a.com"), newAResponse("a.com", 300))
	if _, ok := c.Get(keyA("a.com")); !ok {
		t.Fatal("expected hit")
	}
	clock.Advance(301 * time.Second)
	if _, ok := c.Get(keyA("a.com")); ok {
		t.Fatal("expired entry served")
	}
}

func TestTTLClampAndAging(t *testing.T) {
	c, clock := newTestCache(Options{MinTTL: 60 * time.Second, MaxTTL: 120 * time.Second})
	c.Put(keyA("short.com"), newAResponse("short.com", 5))
	clock.Advance(30 * time.Second)
	if _, ok := c.Get(keyA("short.com")); !ok {
		t.Fatal("MinTTL should extend lifetime")
	}
	c.Put(keyA("long.com"), newAResponse("long.com", 86400))
	clock.Advance(100 * time.Second)
	res, ok := c.Get(keyA("long.com"))
	if !ok || res.Answers[0].Header().TTL != 86300 {
		t.Fatalf("want aged TTL 86300, got %v", res)
	}
	clock.Advance(21 * time.Second)
	if _, ok := c.Get(keyA("long.com")); ok {
		t.Fatal("MaxTTL should cap lifetime")
	}
}

func TestNegativeTTLFollowsSOA(t *testing.T) {
	c, clock := newTestCache(defaultOpts())
	c.Put(keyA("nx.com"), newNegative("nx.com", 3, 3600, 30))
	clock.Advance(29 * time.Second)
	if _, ok := c.Get(keyA("nx.com")); !ok {
		t.Fatal("NXDOMAIN should be cached for SOA MINIMUM")
	}
	clock.Advance(2 * time.Second)
	if _, ok := c.Get(keyA("nx.com")); ok {
		t.Fatal("NXDOMAIN outlived SOA MINIMUM")
	}
	// Without SOA the configured ceiling applies; with a large SOA it caps.
	c.Put(keyA("nodata.com"), newNegative("nodata.com", 0, 86400, 86400))
	clock.Advance(5*time.Minute - time.Second)
	if _, ok := c.Get(keyA("nodata.com")); !ok {
		t.Fatal("NODATA should be cached")
	}
	clock.Advance(2 * time.Second)
	if _, ok := c.Get(keyA("nodata.com")); ok {
		t.Fatal("NegativeTTL should cap negative lifetime")
	}
}

func TestUncacheableResponses(t *testing.T) {
	c, _ := newTestCache(defaultOpts())
	c.Put(keyA("servfail.com"), newNegative("servfail.com", 2, 0, 0))
	c.Put(keyA("refused.com"), newNegative("refused.com", 5, 0, 0))
	tc := newAResponse("tc.com", 300)
	tc.Header.TC = 1
	c.Put(keyA("tc.com"), tc)
	if c.Len() != 0 {
		t.Fatalf("SERVFAIL, REFUSED, and truncated replies must not be cached (len %d)", c.Len())
	}
}

func TestKeyNormalizationAndDNSSECBits(t *testing.T) {
	c, _ := newTestCache(defaultOpts())
	c.Put(keyA("Example.COM."), newAResponse("example.com", 300))
	if _, ok := c.Get(keyA("example.com")); !ok {
		t.Fatal("key should be case- and dot-insensitive")
	}
	q := &packet.DNSQuestion{Name: "example.com", Type: packet.DNSTypeA, Class: packet.DNSClassIN}
	if _, ok := c.Get(KeyFor(q, true, false)); ok {
		t.Fatal("DO=1 must not share entries with DO=0")
	}
	if _, ok := c.Get(KeyFor(q, false, true)); ok {
		t.Fatal("CD=1 must not share entries with CD=0")
	}
}

func TestLRUEvictionAndFlush(t *testing.T) {
	c, _ := newTestCache(Options{MaxTTL: time.Hour, MaxEntries: 2})
	c.Put(keyA("a.com"), newAResponse("a.com", 300))
	c.Put(keyA("b.com"), newAResponse("b.com", 300))
	c.Get(keyA("a.com")) // a is now most recent
	c.Put(keyA("c.com"), newAResponse("c.com", 300))
	if _, ok := c.Get(keyA("b.com")); ok {
		t.Fatal("least recently used entry should be evicted")
	}
	if _, ok := c.Get(keyA("a.com")); !ok {
		t.Fatal("recently used entry evicted")
	}
	c.Flush()
	if c.Len() != 0 {
		t.Fatal("Flush left entries")
	}
}

func TestEntriesAreIsolated(t *testing.T) {
	c, _ := newTestCache(defaultOpts())
	resp := newAResponse("a.com", 300)
	c.Put(keyA("a.com"), resp)
	resp.Answers[0].(*packet.DNSResourceRecordA).Address = "9.9.9.9"
	got, _ := c.Get(keyA("a.com"))
	got.Answers[0].Header().TTL = 1
	again, _ := c.Get(keyA("a.com"))
	if again.Answers[0].(*packet.DNSResourceRecordA).Address != "1.2.3.4" || again.Answers[0].Header().TTL != 300 {
		t.Fatal("cache entries alias caller packets")
	}
}
