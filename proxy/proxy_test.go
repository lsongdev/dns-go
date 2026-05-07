package proxy

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/packet"
)

type stubUpstream struct {
	name     string
	err      error
	resp     *packet.DNSPacket
	calls    int
	closed   bool
}

func (s *stubUpstream) Query(req *packet.DNSPacket) (*packet.DNSPacket, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}
func (s *stubUpstream) Close() error { s.closed = true; return nil }

func mockResponse(addr string) *packet.DNSPacket {
	p := &packet.DNSPacket{Header: &packet.DNSHeader{}}
	p.AddAnswer(&packet.DNSResourceRecordA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: "x", Type: packet.DNSTypeA, Class: packet.DNSClassIN, TTL: 300},
		Address:           addr,
	})
	return p
}

func TestFailoverFirstSucceeds(t *testing.T) {
	a := &stubUpstream{name: "a", resp: mockResponse("1.1.1.1")}
	b := &stubUpstream{name: "b", resp: mockResponse("2.2.2.2")}
	p := &Pool{upstreams: []Upstream{a, b}, strategy: "failover"}

	res, err := p.Query(&packet.DNSPacket{Header: &packet.DNSHeader{}})
	if err != nil {
		t.Fatal(err)
	}
	if res != a.resp {
		t.Errorf("expected primary's response")
	}
	if a.calls != 1 || b.calls != 0 {
		t.Errorf("expected only primary called: a=%d b=%d", a.calls, b.calls)
	}
}

func TestFailoverFallsThrough(t *testing.T) {
	a := &stubUpstream{name: "a", err: errors.New("primary down")}
	b := &stubUpstream{name: "b", resp: mockResponse("2.2.2.2")}
	p := &Pool{upstreams: []Upstream{a, b}, strategy: "failover"}

	res, err := p.Query(&packet.DNSPacket{Header: &packet.DNSHeader{}})
	if err != nil {
		t.Fatal(err)
	}
	if res != b.resp {
		t.Errorf("expected secondary's response")
	}
	if a.calls != 1 || b.calls != 1 {
		t.Errorf("expected both called: a=%d b=%d", a.calls, b.calls)
	}
}

func TestFailoverAllFail(t *testing.T) {
	a := &stubUpstream{name: "a", err: errors.New("err-a")}
	b := &stubUpstream{name: "b", err: errors.New("err-b")}
	p := &Pool{upstreams: []Upstream{a, b}, strategy: "failover"}

	_, err := p.Query(&packet.DNSPacket{Header: &packet.DNSHeader{}})
	if err == nil {
		t.Fatal("expected error when all upstreams fail")
	}
	if !strings.Contains(err.Error(), "err-b") {
		t.Errorf("expected last error returned, got %v", err)
	}
}

func TestPoolClose(t *testing.T) {
	a := &stubUpstream{}
	b := &stubUpstream{}
	p := &Pool{upstreams: []Upstream{a, b}}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if !a.closed || !b.closed {
		t.Errorf("expected all upstreams closed")
	}
}

func TestNewPoolBuildsUpstreams(t *testing.T) {
	spec := config.ProxySpec{
		Strategy: "failover",
		Upstreams: []config.UpstreamSpec{
			{Type: "udp", Addr: "1.1.1.1:53", Timeout: config.Duration(3 * time.Second)},
			{Type: "doh", Addr: "https://doh.pub/dns-query", Method: "post", Timeout: config.Duration(5 * time.Second)},
			{Type: "doh", Addr: "https://example.com/dns-query", Method: "get"},
			{Type: "tcp", Addr: "1.1.1.1:53"},
			{Type: "dot", Addr: "1.1.1.1:853"},
		},
	}
	p, err := NewPool(spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(p.upstreams); got != 5 {
		t.Errorf("expected 5 upstreams, got %d", got)
	}
	_ = p.Close()
}

func TestNewPoolUnknownType(t *testing.T) {
	spec := config.ProxySpec{
		Strategy:  "failover",
		Upstreams: []config.UpstreamSpec{{Type: "smoke", Addr: "x"}},
	}
	if _, err := NewPool(spec); err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestNewPoolUnsupportedStrategy(t *testing.T) {
	spec := config.ProxySpec{
		Strategy:  "parallel",
		Upstreams: []config.UpstreamSpec{{Type: "udp", Addr: "1.1.1.1:53"}},
	}
	if _, err := NewPool(spec); err == nil {
		t.Fatal("expected error for parallel strategy")
	}
}
