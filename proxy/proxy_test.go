package proxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

type stubUpstream struct {
	err    error
	resp   *packet.DNSPacket
	calls  int
	closed bool
}

func (s *stubUpstream) Query(ctx context.Context, req *packet.DNSPacket) (*packet.DNSPacket, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

func (s *stubUpstream) Close() error { s.closed = true; return nil }

func response(rcode uint8) *packet.DNSPacket {
	return &packet.DNSPacket{Header: &packet.DNSHeader{QR: packet.DNSResponse, RCode: rcode}}
}

func query() *packet.DNSPacket {
	p := packet.NewPacket()
	p.AddQuestionA("example.com")
	return p
}

func TestFirstUsableAnswerWins(t *testing.T) {
	a := &stubUpstream{resp: response(0)}
	b := &stubUpstream{resp: response(0)}
	res, err := New(a, b).Query(context.Background(), query())
	if err != nil || res != a.resp || b.calls != 0 {
		t.Fatalf("want first upstream only; err=%v b.calls=%d", err, b.calls)
	}
}

func TestFailoverOnErrorAndServfail(t *testing.T) {
	a := &stubUpstream{err: errors.New("timeout")}
	b := &stubUpstream{resp: response(2)} // SERVFAIL
	c := &stubUpstream{resp: response(3)} // NXDOMAIN is a real answer
	res, err := New(a, b, c).Query(context.Background(), query())
	if err != nil || res != c.resp {
		t.Fatalf("want third upstream's NXDOMAIN, got %v %v", res, err)
	}
}

func TestAllFail(t *testing.T) {
	servfail := response(2)
	res, err := New(&stubUpstream{err: errors.New("x")}, &stubUpstream{resp: servfail}).Query(context.Background(), query())
	if err != nil || res != servfail {
		t.Fatal("with only failures, the last SERVFAIL response is returned")
	}
	if _, err := New(&stubUpstream{err: errors.New("x")}).Query(context.Background(), query()); err == nil {
		t.Fatal("want error when nothing responded")
	}
}

func TestCancelledContextStopsFailover(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := &stubUpstream{resp: response(0)}
	if _, err := New(a).Query(ctx, query()); !errors.Is(err, context.Canceled) || a.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, a.calls)
	}
}

func TestCloseClosesAll(t *testing.T) {
	a, b := &stubUpstream{}, &stubUpstream{}
	New(a, b).Close()
	if !a.closed || !b.closed {
		t.Fatal("pool must close every upstream")
	}
}

func TestNewFromSpecs(t *testing.T) {
	pool, err := NewFromSpecs([]Spec{
		{Type: "udp", Addr: "1.1.1.1:53"},
		{Type: "tcp", Addr: "1.1.1.1:53"},
		{Type: "dot", Addr: "1.1.1.1:853", Timeout: time.Second},
		{Type: "doh", Addr: "https://dns.example/dns-query", Method: "get"},
	})
	if err != nil || len(pool.upstreams) != 4 {
		t.Fatalf("NewFromSpecs: %v", err)
	}
	pool.Close()
	for _, specs := range [][]Spec{nil, {{Type: "quic", Addr: "x"}}, {{Type: "doh", Addr: "x", Method: "put"}}} {
		if _, err := NewFromSpecs(specs); err == nil {
			t.Errorf("NewFromSpecs(%+v) should fail", specs)
		}
	}
}
