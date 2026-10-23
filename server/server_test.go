package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

func testQuery() *packet.DNSPacket {
	req := packet.NewPacket()
	req.AddQuestionA("example.com")
	return req
}

var nxdomain = HandlerFunc(func(ctx context.Context, w ResponseWriter, req *packet.DNSPacket) {
	res := packet.NewReply(req)
	res.SetRCode(packet.RCodeNameError)
	res.AddAuthority(&packet.DNSResourceRecordSOA{
		DNSResourceRecord: packet.DNSResourceRecord{Name: "example.com", Type: packet.DNSTypeSOA, Class: packet.DNSClassIN, TTL: 3600},
		MName:             "ns.example.com", RName: "admin.example.com", Minimum: 300,
	})
	_ = w.WriteMsg(res)
})

func TestUDPLimit(t *testing.T) {
	withOPT := func(size uint16) *packet.DNSPacket {
		p := testQuery()
		p.SetOPT(packet.NewEDNSRecord(size))
		return p
	}
	cases := []struct {
		req  *packet.DNSPacket
		want int
	}{
		{testQuery(), 512},
		{withOPT(100), 512},
		{withOPT(1000), 1000},
		{withOPT(4096), DefaultUDPSize},
	}
	for _, c := range cases {
		if got := UDPLimit(c.req, DefaultUDPSize); got != c.want {
			t.Errorf("UDPLimit = %d, want %d", got, c.want)
		}
	}
}

func TestTCPIsLengthPrefixedAndPipelined(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		(&TCPServer{Handler: nxdomain}).serveConn(serverConn)
		close(done)
	}()
	for i := 0; i < 2; i++ {
		data := testQuery().Bytes()
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(data)))
		if _, err := clientConn.Write(append(frame, data...)); err != nil {
			t.Fatal(err)
		}
		var length [2]byte
		if _, err := io.ReadFull(clientConn, length[:]); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			t.Fatal(err)
		}
		res, err := packet.FromBytes(buf)
		if err != nil || res.RCode() != packet.RCodeNameError {
			t.Fatalf("res=%v err=%v", res, err)
		}
	}
	clientConn.Close()
	<-done
}

func TestTCPIdleTimeoutClosesConnection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	done := make(chan struct{})
	go func() {
		(&TCPServer{Handler: nxdomain, IdleTimeout: 50 * time.Millisecond}).serveConn(serverConn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle connection was not closed")
	}
}

func TestServeReturnsWhenClosed(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	go func() { errs <- (&UDPServer{Handler: nxdomain}).Serve(udp) }()
	go func() { errs <- (&TCPServer{Handler: nxdomain}).Serve(tcp) }()
	udp.Close()
	tcp.Close()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("Serve after Close = %v, want nil", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Serve did not return after Close")
		}
	}
}

func TestDoHGETAndPOST(t *testing.T) {
	h := NewHTTPHandler(nxdomain)
	data := testQuery().Bytes()
	post := httptest.NewRequest(http.MethodPost, DoHPath, bytes.NewReader(data))
	post.Header.Set("Content-Type", "application/dns-message")
	for name, req := range map[string]*http.Request{
		"GET":  httptest.NewRequest(http.MethodGet, DoHPath+"?dns="+base64.RawURLEncoding.EncodeToString(data), nil),
		"POST": post,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/dns-message" {
				t.Fatalf("status %d, content type %q", w.Code, w.Header().Get("Content-Type"))
			}
			// RFC 8484 §5.1: freshness is the smallest TTL, here SOA MINIMUM.
			if got := w.Header().Get("Cache-Control"); got != "max-age=300" {
				t.Fatalf("Cache-Control = %q", got)
			}
			res, err := packet.FromBytes(w.Body.Bytes())
			if err != nil || res.RCode() != packet.RCodeNameError {
				t.Fatalf("res=%v err=%v", res, err)
			}
		})
	}
}

func TestDoHRejectsInvalidRequests(t *testing.T) {
	h := NewHTTPHandler(nxdomain)
	cases := []struct {
		name string
		req  *http.Request
		want int
	}{
		{"missing GET parameter", httptest.NewRequest(http.MethodGet, DoHPath, nil), http.StatusBadRequest},
		{"wrong POST content type", httptest.NewRequest(http.MethodPost, DoHPath, bytes.NewReader(testQuery().Bytes())), http.StatusBadRequest},
		{"unsupported method", httptest.NewRequest(http.MethodDelete, DoHPath, nil), http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, c.req)
			if w.Code != c.want {
				t.Fatalf("status %d, want %d", w.Code, c.want)
			}
		})
	}
}

func TestDoHHandlerThatDoesNotReply(t *testing.T) {
	h := NewHTTPHandler(HandlerFunc(func(context.Context, ResponseWriter, *packet.DNSPacket) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, DoHPath+"?dns="+base64.RawURLEncoding.EncodeToString(testQuery().Bytes()), nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", w.Code)
	}
}
