package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
}

type seen struct {
	addr     netip.AddrPort
	clientID string
}

func recordingHandler(out *seen) Handler {
	return HandlerFunc(func(ctx context.Context, w ResponseWriter, req *packet.DNSPacket) {
		out.addr, out.clientID = w.RemoteAddr(), w.ClientID()
		_ = w.WriteMsg(packet.NewReply(req))
	})
}

func dohGET(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, path+"?dns="+base64.RawURLEncoding.EncodeToString(testQuery().Bytes()), nil)
}

func TestDoHClientIDFromPath(t *testing.T) {
	var got seen
	h := NewHTTPHandler(recordingHandler(&got))
	cases := map[string]struct {
		status int
		id     string
	}{
		"/dns-query":          {200, ""},
		"/dns-query/Laptop-1": {200, "laptop-1"},
		"/dns-query/a/b":      {404, ""},
		"/dns-query/bad_id":   {404, ""},
		"/dns-query/":         {404, ""},
		"/other":              {404, ""},
	}
	for path, want := range cases {
		got = seen{}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, dohGET(path))
		if w.Code != want.status || got.clientID != want.id {
			t.Errorf("%s: status %d id %q, want %d %q", path, w.Code, got.clientID, want.status, want.id)
		}
	}
}

func TestDoHTrustedProxies(t *testing.T) {
	var got seen
	h := &DoHHandler{Handler: recordingHandler(&got), TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}}
	cases := []struct {
		peer, xff, realIP, want string
	}{
		{"203.0.113.9:4000", "1.1.1.1", "", "203.0.113.9"},                        // untrusted peer: header ignored
		{"127.0.0.1:4000", "", "", "127.0.0.1"},                                   // trusted peer, no header
		{"127.0.0.1:4000", "198.51.100.7", "", "198.51.100.7"},                    // single hop
		{"127.0.0.1:4000", "6.6.6.6, 198.51.100.7, 10.0.0.2", "", "198.51.100.7"}, // spoofed leftmost entry ignored
		{"127.0.0.1:4000", "", "198.51.100.8", "198.51.100.8"},                    // X-Real-IP fallback
		{"[::ffff:127.0.0.1]:4000", "198.51.100.7", "", "198.51.100.7"},           // mapped peer
	}
	for _, c := range cases {
		req := dohGET(DoHPath)
		req.RemoteAddr = c.peer
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.realIP != "" {
			req.Header.Set("X-Real-IP", c.realIP)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		if got.addr.Addr().String() != c.want {
			t.Errorf("peer=%s xff=%q: got %s, want %s", c.peer, c.xff, got.addr.Addr(), c.want)
		}
	}
}

func TestClientIDFromSNI(t *testing.T) {
	cases := map[[2]string]string{
		{"laptop.dns.example.com", "dns.example.com"}:   "laptop",
		{"LAPTOP.dns.example.com.", "DNS.example.com"}:  "laptop",
		{"dns.example.com", "dns.example.com"}:          "",
		{"a.b.dns.example.com", "dns.example.com"}:      "",
		{"laptop.dns.example.com", ""}:                  "",
		{"laptop.other.example.com", "dns.example.com"}: "",
	}
	for in, want := range cases {
		if got := clientIDFromSNI(in[0], in[1]); got != want {
			t.Errorf("clientIDFromSNI(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestDoTClientIDFromSNI(t *testing.T) {
	cert := selfSigned(t, "*.dns.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var got seen
	go (&TCPServer{Handler: recordingHandler(&got), Transport: TransportDoT, Hostname: "dns.test"}).Serve(ln)

	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "router.dns.test", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	data := testQuery().Bytes()
	conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(data))), data...))
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		t.Fatal(err)
	}
	if got.clientID != "router" || !got.addr.Addr().IsLoopback() {
		t.Fatalf("got %+v", got)
	}
}

func selfSigned(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
