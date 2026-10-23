package client

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/server"
)

func testQuery(name string) *packet.DNSPacket {
	req := packet.NewPacket()
	req.AddQuestionTXT(name)
	return req
}

// testHandler answers "big." with 40 TXT records (too large for UDP),
// "slow." after a delay, and everything else with NXDOMAIN.
func testHandler(ctx context.Context, w server.ResponseWriter, req *packet.DNSPacket) {
	res := packet.NewReply(req)
	switch req.Questions[0].Name {
	case "big.example":
		for i := 0; i < 40; i++ {
			res.AddAnswer(&packet.DNSResourceRecordTXT{
				DNSResourceRecord: packet.DNSResourceRecord{Name: "big.example", Type: packet.DNSTypeTXT, Class: packet.DNSClassIN, TTL: 60},
				Content:           fmt.Sprintf("record-%02d-padding-padding-padding", i),
			})
		}
	case "slow.example":
		time.Sleep(500 * time.Millisecond)
	default:
		res.SetRCode(packet.RCodeNameError)
	}
	_ = w.WriteMsg(res)
}

type countingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

// startServers serves testHandler on UDP and TCP at the same address.
func startServers(t *testing.T) (string, *countingListener) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ln := &countingListener{Listener: tcp}
	h := server.HandlerFunc(testHandler)
	go (&server.UDPServer{Handler: h}).Serve(udp)
	go (&server.TCPServer{Handler: h}).Serve(ln)
	t.Cleanup(func() { udp.Close(); tcp.Close() })
	return tcp.Addr().String(), ln
}

func TestNXDOMAINIsAResponseNotAnError(t *testing.T) {
	addr, _ := startServers(t)
	for _, c := range []Client{NewUDPClient(addr), NewTCPClient(addr)} {
		res, err := c.Query(context.Background(), testQuery("missing.example"))
		if err != nil || res.RCode() != packet.RCodeNameError {
			t.Fatalf("%T: res=%v err=%v", c, res, err)
		}
		c.Close()
	}
}

func TestUDPFallsBackToTCPWhenTruncated(t *testing.T) {
	addr, ln := startServers(t)
	c := NewUDPClient(addr)
	defer c.Close()
	res, err := c.Query(context.Background(), testQuery("big.example"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.TC != 0 || len(res.Answers) != 40 || ln.accepted.Load() != 1 {
		t.Fatalf("want full answer over TCP; TC=%d answers=%d tcp conns=%d", res.Header.TC, len(res.Answers), ln.accepted.Load())
	}
}

func TestConcurrentQueriesDoNotSerialize(t *testing.T) {
	addr, _ := startServers(t)
	for _, c := range []Client{NewUDPClient(addr), NewTCPClient(addr)} {
		slow := make(chan error, 1)
		go func() {
			_, err := c.Query(context.Background(), testQuery("slow.example"))
			slow <- err
		}()
		time.Sleep(50 * time.Millisecond)
		start := time.Now()
		if _, err := c.Query(context.Background(), testQuery("fast.example")); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("%T: fast query waited %v behind a slow one", c, d)
		}
		if err := <-slow; err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
}

func TestTCPReusesConnections(t *testing.T) {
	addr, ln := startServers(t)
	c := NewTCPClient(addr)
	defer c.Close()
	for i := 0; i < 5; i++ {
		if _, err := c.Query(context.Background(), testQuery("missing.example")); err != nil {
			t.Fatal(err)
		}
	}
	if n := ln.accepted.Load(); n != 1 {
		t.Fatalf("sequential queries opened %d connections, want 1", n)
	}
}

func TestUDPIgnoresMismatchedDatagrams(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		req, _ := packet.FromBytes(buf[:n])
		spoofed := packet.NewReply(req)
		spoofed.Header.ID++
		conn.WriteTo(spoofed.Bytes(), addr)
		conn.WriteTo([]byte("garbage"), addr)
		real := packet.NewReply(req)
		real.SetRCode(packet.RCodeNameError)
		conn.WriteTo(real.Bytes(), addr)
	}()
	c := NewUDPClient(conn.LocalAddr().String())
	c.Timeout = time.Second
	res, err := c.Query(context.Background(), testQuery("x.example"))
	if err != nil || res.RCode() != packet.RCodeNameError {
		t.Fatalf("want the genuine reply, got %v %v", res, err)
	}
}

func TestQueryHonorsContext(t *testing.T) {
	addr, _ := startServers(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := NewUDPClient(addr).Query(ctx, testQuery("slow.example")); err == nil {
		t.Fatal("want deadline error")
	}
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Fatalf("context deadline ignored (%v)", d)
	}
}
