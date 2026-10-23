package zone

import (
	"strings"
	"sync"
	"testing"

	"github.com/lsongdev/dns-go/packet"
)

func mustZone(t *testing.T, origin string, kind Kind, records ...string) *Zone {
	t.Helper()
	z, err := ParseString(origin, strings.Join(records, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	z.Kind = kind
	return z
}

func mustStore(t *testing.T, opts StoreOptions, zones ...*Zone) *Store {
	t.Helper()
	s := NewStore(opts)
	if err := s.Replace(zones); err != nil {
		t.Fatal(err)
	}
	return s
}

func exampleZone(t *testing.T) *Zone {
	return mustZone(t, "example.com", Static,
		"@ 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300",
		"@ 300 IN NS ns1.example.com.",
		"ns1 300 IN A 192.0.2.53",
		"www 300 IN A 192.0.2.1",
		"alias 300 IN CNAME www.example.com.",
		"*.wild 300 IN A 192.0.2.2",
		"child 300 IN NS ns.child.example.com.",
		"ns.child 300 IN A 192.0.2.54",
	)
}

func lookupA(s *Store, name string) Result {
	return s.Lookup(name, packet.DNSTypeA, packet.DNSClassIN)
}

func TestStaticNODATAAndNXDOMAIN(t *testing.T) {
	s := mustStore(t, StoreOptions{Authoritative: true}, exampleZone(t))

	r := s.Lookup("www.example.com", packet.DNSTypeAAAA, packet.DNSClassIN)
	if !r.Found || !r.Authoritative || r.RCode != packet.RCodeSuccess || len(r.Answers) != 0 {
		t.Fatalf("want authoritative NODATA, got %+v", r)
	}
	if len(r.Authorities) != 1 || r.Authorities[0].GetType() != packet.DNSTypeSOA {
		t.Fatal("NODATA must carry the SOA")
	}
	r = lookupA(s, "missing.example.com")
	if r.RCode != packet.RCodeNameError || len(r.Authorities) != 1 {
		t.Fatalf("want NXDOMAIN with SOA, got %+v", r)
	}
	if r := lookupA(s, "outside.example"); r.Found {
		t.Fatal("out-of-zone names must not be found")
	}
}

func TestCNAMEChainAndWildcard(t *testing.T) {
	s := mustStore(t, StoreOptions{}, exampleZone(t))
	r := lookupA(s, "alias.example.com")
	if len(r.Answers) != 2 || r.Answers[0].GetType() != packet.DNSTypeCNAME || r.Answers[1].GetType() != packet.DNSTypeA {
		t.Fatalf("want CNAME then A, got %v", r.Answers)
	}
	r = lookupA(s, "host.wild.example.com")
	if len(r.Answers) != 1 {
		t.Fatalf("want wildcard answer, got %d", len(r.Answers))
	}
	a := r.Answers[0].(*packet.DNSResourceRecordA)
	if a.Name != "host.wild.example.com" || a.Address != "192.0.2.2" {
		t.Fatalf("wildcard answer %s %s", a.Name, a.Address)
	}
}

func TestDelegationReferralAndDS(t *testing.T) {
	s := mustStore(t, StoreOptions{}, exampleZone(t))
	r := lookupA(s, "host.child.example.com")
	if r.Authoritative || len(r.Authorities) != 1 || r.Authorities[0].GetType() != packet.DNSTypeNS {
		t.Fatalf("want non-authoritative referral, got %+v", r)
	}
	if len(r.Additionals) != 1 || r.Additionals[0].GetType() != packet.DNSTypeA {
		t.Fatal("want in-bailiwick glue")
	}
	r = s.Lookup("child.example.com", packet.DNSTypeDS, packet.DNSClassIN)
	if !r.Authoritative || len(r.Authorities) != 1 {
		t.Fatalf("DS at a cut is answered by the parent, got %+v", r)
	}
}

func TestLongestMatchingZoneWins(t *testing.T) {
	s := mustStore(t, StoreOptions{},
		mustZone(t, "example.com", Static, "www.sub 60 IN A 192.0.2.1"),
		mustZone(t, "sub.example.com", Static, "www 60 IN A 192.0.2.2"),
	)
	r := lookupA(s, "www.sub.example.com")
	if len(r.Answers) != 1 || r.Answers[0].(*packet.DNSResourceRecordA).Address != "192.0.2.2" {
		t.Fatalf("want child zone answer, got %v", r.Answers)
	}
}

func TestExistingNameSuppressesHigherWildcard(t *testing.T) {
	s := mustStore(t, StoreOptions{}, mustZone(t, "example.com", Static,
		"* 60 IN A 192.0.2.1",
		"host.branch 60 IN TXT present",
	))
	r := lookupA(s, "missing.branch.example.com")
	if r.RCode != packet.RCodeNameError || len(r.Answers) != 0 {
		t.Fatalf("wildcard crossed the closest encloser: %+v", r)
	}
}

func TestTransparentZoneFallsThrough(t *testing.T) {
	s := mustStore(t, StoreOptions{}, mustZone(t, "example.com", Transparent,
		"nas 60 IN A 192.168.1.10",
		"*.lan 60 IN A 192.168.1.20",
	))
	if r := lookupA(s, "nas.example.com"); !r.Found || len(r.Answers) != 1 {
		t.Fatalf("override should answer, got %+v", r)
	}
	if r := s.Lookup("nas.example.com", packet.DNSTypeAAAA, packet.DNSClassIN); !r.Found || len(r.Answers) != 0 {
		t.Fatalf("known name, missing type: want NODATA, got %+v", r)
	}
	if r := lookupA(s, "x.lan.example.com"); !r.Found || len(r.Answers) != 1 {
		t.Fatalf("wildcard override should answer, got %+v", r)
	}
	for _, name := range []string{"www.example.com", "example.com", "lan.example.com"} {
		if r := lookupA(s, name); r.Found {
			t.Fatalf("%s: unknown names must fall through, got %+v", name, r)
		}
	}
}

func TestRootTransparentZoneFromHosts(t *testing.T) {
	z, err := ParseHosts(strings.NewReader(`
# comment
192.168.1.10 nas.home.lan nas   # trailing comment
fd00::10     nas.home.lan
0.0.0.0      ads.example.net
`))
	if err != nil {
		t.Fatal(err)
	}
	s := mustStore(t, StoreOptions{}, z, mustZone(t, "home.lan", Static, "router 60 IN A 192.168.1.1"))
	if r := lookupA(s, "ads.example.net"); len(r.Answers) != 1 {
		t.Fatalf("hosts entry should answer, got %+v", r)
	}
	if r := s.Lookup("nas", packet.DNSTypeA, packet.DNSClassIN); len(r.Answers) != 1 {
		t.Fatalf("single-label alias should answer, got %+v", r)
	}
	if r := lookupA(s, "google.com"); r.Found {
		t.Fatal("names absent from hosts must fall through")
	}
	// The more specific static zone wins over the root hosts zone.
	if r := lookupA(s, "nas.home.lan"); r.RCode != packet.RCodeNameError {
		t.Fatalf("static home.lan owns its namespace, got %+v", r)
	}
	if _, err := ParseHosts(strings.NewReader("not-an-ip host\n")); err == nil {
		t.Fatal("invalid address should be rejected")
	}
}

func TestNonINClassIsNotAnswered(t *testing.T) {
	s := mustStore(t, StoreOptions{}, exampleZone(t))
	if r := s.Lookup("www.example.com", packet.DNSTypeA, packet.DNSClassCH); r.Found {
		t.Fatal("CHAOS queries must not see IN data")
	}
}

func TestStoreCRUD(t *testing.T) {
	s := NewStore(StoreOptions{})
	z := mustZone(t, "Example.COM.", Static, "www 60 IN A 192.0.2.1")
	if err := s.Put(z); err != nil {
		t.Fatal(err)
	}
	z.Records = nil // the store must have copied
	got, ok := s.Get("example.com")
	if !ok || got.Origin != "example.com" || got.Kind != Static || len(got.Records) != 1 {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
	got.Records[0].Header().TTL = 1 // mutating a returned copy must not leak
	if r := lookupA(s, "www.example.com"); r.Answers[0].Header().TTL != 60 {
		t.Fatal("returned zone aliases store data")
	}

	if err := s.Put(mustZone(t, "example.com", Static, "www 60 IN A 192.0.2.9")); err != nil {
		t.Fatal(err)
	}
	if r := lookupA(s, "www.example.com"); r.Answers[0].(*packet.DNSResourceRecordA).Address != "192.0.2.9" {
		t.Fatal("Put did not replace the zone")
	}
	if err := s.Put(mustZone(t, "other.example", Transparent, "a 60 IN A 192.0.2.3")); err != nil {
		t.Fatal(err)
	}
	if list := s.List(); len(list) != 2 || list[0].Origin != "example.com" || list[1].Origin != "other.example" {
		t.Fatalf("List = %v", list)
	}
	if !s.Delete("example.com.") || s.Delete("example.com") {
		t.Fatal("Delete should report existence")
	}
	if r := lookupA(s, "www.example.com"); r.Found {
		t.Fatal("deleted zone still answers")
	}
}

func TestAuthoritativePolicy(t *testing.T) {
	s := NewStore(StoreOptions{Authoritative: true})
	if err := s.Put(mustZone(t, "example.com", Static, "@ IN A 192.0.2.1")); err == nil {
		t.Fatal("zone without SOA and NS must be rejected")
	}
	z := exampleZone(t)
	z.Kind = Transparent
	if err := s.Put(z); err == nil {
		t.Fatal("transparent zones must be rejected")
	}
}

func TestInvalidZoneDataRejectedAndLastGoodKept(t *testing.T) {
	s := mustStore(t, StoreOptions{}, exampleZone(t))
	tests := map[string][]string{
		"CNAME conflict": {"alias IN CNAME target.example.com.", "alias IN A 192.0.2.1"},
		"multiple CNAME": {"alias IN CNAME one.example.com.", "alias IN CNAME two.example.com."},
		"apex CNAME":     {"@ IN CNAME target.example.net."},
		"CNAME cycle":    {"one IN CNAME two.example.com.", "two IN CNAME one.example.com."},
		"SOA below apex": {"child IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 5"},
		"outside zone":   {"www.example.net. IN A 192.0.2.1"},
	}
	for name, records := range tests {
		t.Run(name, func(t *testing.T) {
			if err := s.Put(mustZone(t, "example.com", Static, records...)); err == nil {
				t.Fatal("invalid zone accepted")
			}
			if r := lookupA(s, "www.example.com"); len(r.Answers) != 1 {
				t.Fatal("failed Put discarded the last good zone")
			}
		})
	}
	if err := s.Replace([]*Zone{exampleZone(t), exampleZone(t)}); err == nil {
		t.Fatal("duplicate origins must be rejected")
	}
}

func TestConcurrentLookupsDuringWrites(t *testing.T) {
	s := mustStore(t, StoreOptions{}, exampleZone(t))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				lookupA(s, "www.example.com")
				lookupA(s, "new.example")
			}
		}()
	}
	for i := 0; i < 100; i++ {
		if err := s.Put(mustZone(t, "new.example", Static, "@ 60 IN A 192.0.2.10")); err != nil {
			t.Fatal(err)
		}
		s.Delete("new.example")
	}
	wg.Wait()
}

func TestModernRecordTypes(t *testing.T) {
	s := mustStore(t, StoreOptions{}, mustZone(t, "example.com", Static,
		"@ 300 IN CAA 0 issue ca.example",
		"@ 300 IN DNSKEY 257 3 13 AQIDBA==",
		"@ 300 IN HTTPS 1 svc.example.com. alpn=h2",
	))
	for _, rtype := range []packet.DNSType{packet.DNSTypeCAA, packet.DNSTypeDNSKEY, packet.DNSTypeHTTPS} {
		r := s.Lookup("example.com", rtype, packet.DNSClassIN)
		if len(r.Answers) != 1 || r.Answers[0].GetType() != rtype {
			t.Fatalf("type %d not served: %v", rtype, r.Answers)
		}
	}
}
