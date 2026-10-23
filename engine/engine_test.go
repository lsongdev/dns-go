package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lsongdev/dns-go/cache"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/server"
	"github.com/lsongdev/dns-go/zone"
)

// stubUpstream answers every query with an A record (or its configured
// response) and records what it was asked.
type stubUpstream struct {
	mu      sync.Mutex
	err     error
	rcode   uint8
	ad      bool
	addr    string
	padding bool
	queries []*packet.DNSPacket
}

func (s *stubUpstream) Query(ctx context.Context, req *packet.DNSPacket) (*packet.DNSPacket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, req)
	if s.err != nil {
		return nil, s.err
	}
	res := packet.NewReply(req)
	res.Header.RA = 1
	res.Header.RCode = s.rcode
	if s.ad {
		res.Header.AD = 1
	}
	q := req.Questions[0]
	if s.rcode == 0 && q.Type == packet.DNSTypeA {
		addr := s.addr
		if addr == "" {
			addr = "203.0.113.1"
		}
		res.AddAnswer(aRecord(q.Name, addr))
	}
	opt := packet.NewEDNSRecord(4096)
	if s.padding {
		opt.AddEDNSOptionPadding(400)
	}
	res.SetOPT(opt)
	return res, nil
}

func (s *stubUpstream) Close() error { return nil }

func (s *stubUpstream) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queries)
}

func aRecord(name, addr string) *packet.DNSResourceRecordA {
	return &packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: name, Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: 300},
		Address:           addr,
	}
}

func query(name string, qtype packet.DNSType) *packet.DNSPacket {
	p := &packet.DNSPacket{Header: &packet.DNSHeader{ID: 0x1234, RD: 1}}
	p.AddQuestion(&packet.DNSQuestion{Name: name, Type: qtype, Class: packet.DNSClassIN})
	return p
}

func withEDNS(p *packet.DNSPacket, do bool) *packet.DNSPacket {
	opt := packet.NewEDNSRecord(4096)
	opt.SetDNSSECOK(do)
	p.SetOPT(opt)
	return p
}

func zones(t *testing.T, authoritative bool, zs ...*zone.Zone) *zone.Store {
	t.Helper()
	s := zone.NewStore(zone.StoreOptions{Authoritative: authoritative})
	if err := s.Replace(zs); err != nil {
		t.Fatal(err)
	}
	return s
}

func mkZone(t *testing.T, origin string, kind zone.Kind, records ...string) *zone.Zone {
	t.Helper()
	z, err := zone.ParseString(origin, strings.Join(records, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	z.Kind = kind
	return z
}

func authZone(t *testing.T) *zone.Zone {
	return mkZone(t, "example.com", zone.Static,
		"@ 300 IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 300",
		"@ 300 IN NS ns1.example.com.",
		"ns1 300 IN A 192.0.2.53",
		"www 300 IN A 192.0.2.1",
		"www 300 IN RRSIG A 13 3 300 20300101000000 20200101000000 12345 example.com. AQID",
	)
}

func forwarder(t *testing.T, up *stubUpstream, rules ...string) *Engine {
	t.Helper()
	f := filter.New()
	f.SetList(filter.List{Name: "test", Rules: rules})
	return New(Options{
		Zones:    zones(t, false),
		Filter:   f,
		Cache:    cache.New(cache.Options{MaxTTL: time.Hour, NegativeTTL: time.Minute, MaxEntries: 100}),
		Upstream: up,
	})
}

func resolve(e *Engine, req *packet.DNSPacket) Result {
	res := e.Resolve(context.Background(), req)
	// Round-trip through the wire format, as a client would see it.
	decoded, err := packet.FromBytes(res.Msg.Bytes())
	if err != nil {
		panic(err)
	}
	res.Msg = decoded
	return res
}

func TestForwardThenCache(t *testing.T) {
	up := &stubUpstream{}
	e := forwarder(t, up)
	for i, want := range []Source{SourceUpstream, SourceCache} {
		r := resolve(e, query("google.com", packet.DNSTypeA))
		if r.Source != want || len(r.Msg.Answers) != 1 || r.Msg.Header.ID != 0x1234 || r.Msg.Header.RA != 1 {
			t.Fatalf("query %d: source=%s answers=%d id=%#x", i, r.Source, len(r.Msg.Answers), r.Msg.Header.ID)
		}
	}
	if up.calls() != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls())
	}
}

func TestUpstreamQueryIsFreshAndCarriesDOAndCD(t *testing.T) {
	up := &stubUpstream{}
	e := forwarder(t, up)
	req := withEDNS(query("google.com", packet.DNSTypeA), true)
	req.Header.CD = 1
	req.OPT().AddEDNSOptionCookie([]byte("12345678"), nil)
	resolve(e, req)
	uq := up.queries[0]
	opt := uq.OPT()
	if uq.Header.RD != 1 || uq.Header.CD != 1 || opt == nil || !opt.GetDNSSECOK() || len(opt.Options) != 0 {
		t.Fatalf("upstream query header=%+v opt=%+v", uq.Header, opt)
	}
}

func TestEDNSHandling(t *testing.T) {
	up := &stubUpstream{padding: true}
	e := forwarder(t, up)

	r := resolve(e, query("a.com", packet.DNSTypeA))
	if r.Msg.OPT() != nil {
		t.Fatal("no OPT in request: reply must not carry one")
	}
	r = resolve(e, withEDNS(query("b.com", packet.DNSTypeA), true))
	opt := r.Msg.OPT()
	if opt == nil || opt.UDPSize != server.DefaultUDPSize || !opt.GetDNSSECOK() || len(opt.Options) != 0 {
		t.Fatalf("reply OPT = %+v (upstream options must not leak)", opt)
	}

	bad := withEDNS(query("c.com", packet.DNSTypeA), false)
	bad.OPT().Version = 1
	r = resolve(e, bad)
	if r.Msg.RCode() != packet.RCodeBadVersion || r.Msg.OPT() == nil || up.calls() != 2 {
		t.Fatalf("EDNS version 1: rcode=%d", r.Msg.RCode())
	}

	two := withEDNS(query("d.com", packet.DNSTypeA), false)
	two.AddAdditional(packet.NewEDNSRecord(512))
	if r := resolve(e, two); r.Msg.RCode() != packet.RCodeFormatError {
		t.Fatalf("two OPT records: rcode=%d", r.Msg.RCode())
	}
}

func TestADBit(t *testing.T) {
	up := &stubUpstream{ad: true}
	e := forwarder(t, up)
	if r := resolve(e, query("a.com", packet.DNSTypeA)); r.Msg.Header.AD != 0 {
		t.Fatal("AD must not be sent to clients that did not ask (RFC 6840 §5.8)")
	}
	if r := resolve(e, withEDNS(query("b.com", packet.DNSTypeA), true)); r.Msg.Header.AD != 1 {
		t.Fatal("DO=1 client should see upstream AD")
	}
	req := query("c.com", packet.DNSTypeA)
	req.Header.AD = 1
	if r := resolve(e, req); r.Msg.Header.AD != 1 {
		t.Fatal("AD=1 client should see upstream AD")
	}

	auth := New(Options{Zones: zones(t, true, authZone(t))})
	req = withEDNS(query("www.example.com", packet.DNSTypeA), true)
	req.Header.AD, req.Header.CD = 1, 1
	r := resolve(auth, req)
	if r.Msg.Header.AD != 0 || r.Msg.Header.CD != 1 || r.Msg.Header.AA != 1 {
		t.Fatalf("authoritative reply header %+v: AD must be clear, CD echoed", r.Msg.Header)
	}
}

func TestInvalidRequests(t *testing.T) {
	e := forwarder(t, &stubUpstream{})
	noQuestion := &packet.DNSPacket{Header: &packet.DNSHeader{ID: 1}}
	twoQuestions := query("a.com", packet.DNSTypeA)
	twoQuestions.AddQuestionA("b.com")
	notify := query("a.com", packet.DNSTypeSOA)
	notify.Header.OpCode = uint8(packet.DNSOpCodeNotify)
	cases := map[string]struct {
		req  *packet.DNSPacket
		want uint16
	}{
		"no question":   {noQuestion, packet.RCodeFormatError},
		"two questions": {twoQuestions, packet.RCodeFormatError},
		"opcode":        {notify, packet.RCodeNotImplemented},
		"AXFR":          {query("example.com", packet.DNSTypeAXFR), packet.RCodeRefused},
		"IXFR":          {query("example.com", packet.DNSTypeIXFR), packet.RCodeRefused},
	}
	for name, c := range cases {
		if r := resolve(e, c.req); r.Msg.RCode() != c.want {
			t.Errorf("%s: rcode=%d want %d", name, r.Msg.RCode(), c.want)
		}
	}
}

func TestAuthoritativeMode(t *testing.T) {
	e := New(Options{Zones: zones(t, true, authZone(t))})
	r := resolve(e, query("www.example.com", packet.DNSTypeA))
	if r.Msg.Header.AA != 1 || r.Msg.Header.RA != 0 || len(r.Msg.Answers) != 1 {
		t.Fatalf("authoritative answer header=%+v answers=%d", r.Msg.Header, len(r.Msg.Answers))
	}
	r = resolve(e, query("outside.example", packet.DNSTypeA))
	if r.Msg.RCode() != packet.RCodeRefused || r.Msg.Header.RA != 0 || r.Source != SourcePolicy {
		t.Fatalf("out-of-zone: rcode=%d RA=%d", r.Msg.RCode(), r.Msg.Header.RA)
	}
	if r := resolve(e, query("missing.example.com", packet.DNSTypeA)); r.Msg.RCode() != packet.RCodeNameError || len(r.Msg.Authorities) != 1 {
		t.Fatal("NXDOMAIN with SOA expected")
	}
}

func TestDNSSECRecordsOnlyForDO(t *testing.T) {
	e := New(Options{Zones: zones(t, true, authZone(t))})
	if r := resolve(e, query("www.example.com", packet.DNSTypeA)); len(r.Msg.Answers) != 1 {
		t.Fatalf("DO=0: want A only, got %d records", len(r.Msg.Answers))
	}
	if r := resolve(e, withEDNS(query("www.example.com", packet.DNSTypeA), true)); len(r.Msg.Answers) != 2 {
		t.Fatalf("DO=1: want A and RRSIG, got %d records", len(r.Msg.Answers))
	}
	if r := resolve(e, query("www.example.com", packet.DNSTypeRRSIG)); len(r.Msg.Answers) != 1 {
		t.Fatal("explicit RRSIG query must return RRSIG")
	}
}

func TestStaticZoneDoesNotLeakUpstream(t *testing.T) {
	up := &stubUpstream{}
	e := forwarder(t, up, "||missing.home.lan^")
	e.zones.Put(mkZone(t, "home.lan", zone.Static, "nas 60 IN A 192.168.1.10"))
	if r := resolve(e, query("nas.home.lan", packet.DNSTypeA)); r.Source != SourceZone || len(r.Msg.Answers) != 1 {
		t.Fatalf("local answer source=%s", r.Source)
	}
	if r := resolve(e, query("missing.home.lan", packet.DNSTypeA)); r.Msg.RCode() != packet.RCodeNameError || r.Source != SourceZone {
		t.Fatalf("static zone must answer NXDOMAIN itself, got rcode=%d source=%s", r.Msg.RCode(), r.Source)
	}
	if up.calls() != 0 {
		t.Fatalf("static zone leaked %d queries upstream", up.calls())
	}
}

func TestTransparentOverrideAndCNAMEChase(t *testing.T) {
	up := &stubUpstream{addr: "198.51.100.7"}
	e := forwarder(t, up)
	e.zones.Put(mkZone(t, "example.com", zone.Transparent,
		"dev 60 IN A 192.168.1.50",
		"www 60 IN CNAME cdn.example.net.",
	))
	if r := resolve(e, query("dev.example.com", packet.DNSTypeA)); r.Source != SourceZone || up.calls() != 0 {
		t.Fatal("override should answer locally")
	}
	if r := resolve(e, query("api.example.com", packet.DNSTypeA)); r.Source != SourceUpstream {
		t.Fatalf("other names should go upstream, source=%s", r.Source)
	}
	r := resolve(e, query("www.example.com", packet.DNSTypeA))
	if len(r.Msg.Answers) != 2 || r.Msg.Answers[1].(*packet.DNSResourceRecordA).Address != "198.51.100.7" {
		t.Fatalf("CNAME target should be resolved upstream, answers=%v", r.Msg.Answers)
	}
	if r.Msg.Header.AA != 0 {
		t.Fatal("a chased answer is not authoritative")
	}
	if q := up.queries[len(up.queries)-1].Questions[0]; q.Name != "cdn.example.net" {
		t.Fatalf("chased %q", q.Name)
	}
}

func TestFilterBlocking(t *testing.T) {
	up := &stubUpstream{}
	e := forwarder(t, up, "||ads.com^", "@@||ok.ads.com^")

	r := resolve(e, query("x.ads.com", packet.DNSTypeA))
	if r.Source != SourceFilter || r.Filter.Rule != "||ads.com^" || r.Msg.Answers[0].(*packet.DNSResourceRecordA).Address != "0.0.0.0" {
		t.Fatalf("A block: %+v", r)
	}
	if r := resolve(e, query("x.ads.com", packet.DNSTypeAAAA)); r.Msg.Answers[0].(*packet.DNSResourceRecordAAAA).Address != "::" {
		t.Fatal("AAAA block should be ::")
	}
	if r := resolve(e, query("x.ads.com", packet.DNSTypeHTTPS)); r.Msg.RCode() != packet.RCodeSuccess || len(r.Msg.Answers) != 0 {
		t.Fatal("other types should be NODATA, not NXDOMAIN (the name exists for A)")
	}
	if r := resolve(e, query("ok.ads.com", packet.DNSTypeA)); r.Source != SourceUpstream || r.Filter.Action != filter.Allow {
		t.Fatalf("allowed name should resolve and report the allow rule: %+v", r)
	}
	e.SetBlockMode(BlockNXDomain)
	if r := resolve(e, query("x.ads.com", packet.DNSTypeA)); r.Msg.RCode() != packet.RCodeNameError {
		t.Fatal("nxdomain block mode")
	}
	e.SetBlockMode(BlockRefused)
	if r := resolve(e, query("x.ads.com", packet.DNSTypeA)); r.Msg.RCode() != packet.RCodeRefused {
		t.Fatal("refused block mode")
	}
	if up.calls() != 1 || e.cache.Len() != 1 {
		t.Fatalf("blocked answers must not reach upstream or cache (calls=%d cache=%d)", up.calls(), e.cache.Len())
	}
}

func TestFilterAppliesBeforeCache(t *testing.T) {
	e := forwarder(t, &stubUpstream{})
	resolve(e, query("tracker.com", packet.DNSTypeA)) // cached
	e.filter.SetList(filter.List{Name: "new", Rules: []string{"||tracker.com^"}})
	if r := resolve(e, query("tracker.com", packet.DNSTypeA)); r.Source != SourceFilter {
		t.Fatalf("a newly added rule must win over a cached answer, source=%s", r.Source)
	}
}

func TestUpstreamFailure(t *testing.T) {
	e := forwarder(t, &stubUpstream{err: errors.New("boom")})
	r := resolve(e, query("a.com", packet.DNSTypeA))
	if r.Msg.RCode() != packet.RCodeServerFailure || r.Source != SourceError || r.Err == nil {
		t.Fatalf("want SERVFAIL with error, got rcode=%d source=%s", r.Msg.RCode(), r.Source)
	}
	if e.cache.Len() != 0 {
		t.Fatal("SERVFAIL must not be cached")
	}
}

// TestUDPTruncationEndToEnd serves a large authoritative RRset over a real
// UDP socket to a client without EDNS.
func TestUDPTruncationEndToEnd(t *testing.T) {
	records := []string{
		"@ 300 IN SOA ns1.t.test. admin.t.test. 1 3600 600 86400 300",
		"@ 300 IN NS ns1.t.test.",
	}
	for i := 0; i < 40; i++ {
		records = append(records, fmt.Sprintf(`big 300 IN TXT "record-%02d-padding-padding-padding-padding"`, i))
	}
	e := New(Options{Zones: zones(t, true, mkZone(t, "t.test", zone.Static, records...))})
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go (&server.UDPServer{Handler: e}).Serve(conn)

	exchange := func(req *packet.DNSPacket) (*packet.DNSPacket, int) {
		c, err := net.Dial("udp", conn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write(req.Bytes())
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		res, err := packet.FromBytes(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		return res, n
	}
	res, n := exchange(query("big.t.test", packet.DNSTypeTXT))
	if res.Header.TC != 1 || n > 512 {
		t.Fatalf("no EDNS: want TC within 512 bytes, got TC=%d size=%d", res.Header.TC, n)
	}
	res, n = exchange(withEDNS(query("big.t.test", packet.DNSTypeTXT), false))
	if res.Header.TC != 1 || n > server.DefaultUDPSize || res.OPT() == nil {
		t.Fatalf("EDNS 4096: want TC within %d bytes, got TC=%d size=%d", server.DefaultUDPSize, res.Header.TC, n)
	}
	res, _ = exchange(withEDNS(query("ns1.t.test", packet.DNSTypeNS), false))
	if res.Header.TC != 0 {
		t.Fatal("small answer must not be truncated")
	}
}

type recordingWriter struct{ msg *packet.DNSPacket }

func (w *recordingWriter) WriteMsg(m *packet.DNSPacket) error { w.msg = m; return nil }
func (w *recordingWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 5353}
}
func (w *recordingWriter) Transport() server.Transport { return server.TransportUDP }

func TestServeDNSEmitsQueryEvent(t *testing.T) {
	var events []QueryEvent
	f := filter.New()
	f.SetList(filter.List{Name: "ads", Rules: []string{"||ads.com^"}})
	e := New(Options{Zones: zones(t, false), Filter: f, Upstream: &stubUpstream{}, OnQuery: func(ev QueryEvent) { events = append(events, ev) }})
	w := &recordingWriter{}
	e.ServeDNS(context.Background(), w, query("x.ads.com", packet.DNSTypeA))
	if w.msg == nil || len(events) != 1 {
		t.Fatal("reply or event missing")
	}
	ev := events[0]
	if ev.Name != "x.ads.com" || ev.Source != SourceFilter || ev.Filter.List != "ads" || ev.Transport != server.TransportUDP || ev.Answers != 1 {
		t.Fatalf("event = %+v", ev)
	}

	response := query("a.com", packet.DNSTypeA)
	response.Header.QR = packet.DNSResponse
	w.msg = nil
	e.ServeDNS(context.Background(), w, response)
	if w.msg != nil {
		t.Fatal("responses must never be answered")
	}
}

func TestServiceFromConfigAndReload(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hosts, []byte("192.168.1.9 printer.lan\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	list := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(list, []byte("||listed.com^\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := fmt.Sprintf(`
listens: [{type: udp, addr: "127.0.0.1:0"}]
upstreams: [{type: udp, addr: "127.0.0.1:1"}]
cache: {enabled: true}
domains:
  - domain: home.lan
    records: ["nas 60 IN A 192.168.1.10"]
  - hosts_file: %s
filters:
  block_mode: nxdomain
  lists: [{name: local, file: %s}]
  rules: ["||inline.com^"]
`, hosts, list)
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	e := svc.Engine
	check := func(name string, wantRCode uint16, wantSource Source) {
		t.Helper()
		r := resolve(e, query(name, packet.DNSTypeA))
		if r.Msg.RCode() != wantRCode || r.Source != wantSource {
			t.Fatalf("%s: rcode=%d source=%s, want %d %s", name, r.Msg.RCode(), r.Source, wantRCode, wantSource)
		}
	}
	check("nas.home.lan", packet.RCodeSuccess, SourceZone)
	check("printer.lan", packet.RCodeSuccess, SourceZone)
	check("listed.com", packet.RCodeNameError, SourceFilter)
	check("inline.com", packet.RCodeNameError, SourceFilter)

	cfg.Domains = cfg.Domains[:1]
	cfg.Domains[0].Records = []string{"nas 60 IN A 192.168.1.11"}
	cfg.Filters.Rules = nil
	cfg.Filters.BlockMode = "zero_ip"
	if err := svc.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	if r := resolve(e, query("nas.home.lan", packet.DNSTypeA)); r.Msg.Answers[0].(*packet.DNSResourceRecordA).Address != "192.168.1.11" {
		t.Fatal("reload did not replace zone data")
	}
	if r := resolve(e, query("listed.com", packet.DNSTypeA)); r.Msg.RCode() != packet.RCodeSuccess || r.Source != SourceFilter {
		t.Fatal("reload did not change block mode")
	}
	if r := resolve(e, query("printer.lan", packet.DNSTypeA)); r.Source == SourceZone {
		t.Fatal("removed hosts zone still answers")
	}
	if r := resolve(e, query("inline.com", packet.DNSTypeA)); r.Source == SourceFilter {
		t.Fatal("removed inline rule still blocks")
	}

	bad := *cfg
	bad.Domains = []config.DomainSpec{{Domain: "home.lan", Kind: "static", Records: []string{"x IN CNAME y.", "x IN A 1.2.3.4"}}}
	if err := svc.Apply(&bad); err == nil {
		t.Fatal("invalid zone data must be rejected")
	}
	if r := resolve(e, query("nas.home.lan", packet.DNSTypeA)); len(r.Msg.Answers) != 1 {
		t.Fatal("failed reload must keep the running zones")
	}
	bad = *cfg
	bad.Mode = config.ModeAuthoritative
	if err := svc.Apply(&bad); err == nil {
		t.Fatal("mode changes need a restart")
	}
}
