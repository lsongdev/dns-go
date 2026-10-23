package server

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

// DoHPath is the conventional RFC 8484 endpoint.
const DoHPath = "/dns-query"

const dnsMessageType = "application/dns-message"

// NewHTTPServer returns an http.Server that serves DoH at DoHPath. Callers
// that also serve an API can instead mount NewHTTPHandler on their own mux.
func NewHTTPServer(addr string, h Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(DoHPath, NewHTTPHandler(h))
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// ListenHTTP serves DoH over plain HTTP, for use behind a TLS-terminating
// reverse proxy.
func ListenHTTP(addr string, h Handler) error {
	return NewHTTPServer(addr, h).ListenAndServe()
}

// ListenHTTPS serves DoH over HTTPS (HTTP/2 when the client supports it).
func ListenHTTPS(addr string, config *tls.Config, h Handler) error {
	srv := NewHTTPServer(addr, h)
	srv.TLSConfig = config
	ln, err := tls.Listen("tcp", addr, withHTTP2(config))
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func withHTTP2(config *tls.Config) *tls.Config {
	c := config.Clone()
	if len(c.NextProtos) == 0 {
		c.NextProtos = []string{"h2", "http/1.1"}
	}
	return c
}

// NewHTTPHandler returns an RFC 8484 DNS-over-HTTPS handler.
func NewHTTPHandler(h Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		data, err := readDoHRequest(r)
		if err != nil {
			status := http.StatusBadRequest
			var methodErr *methodNotAllowedError
			if errors.As(err, &methodErr) {
				rw.Header().Set("Allow", "GET, POST")
				status = http.StatusMethodNotAllowed
			}
			http.Error(rw, err.Error(), status)
			return
		}
		req, err := packet.FromBytes(data)
		if err != nil {
			http.Error(rw, "invalid DNS message", http.StatusBadRequest)
			return
		}
		w := &httpWriter{rw: rw, remote: httpRemoteAddr(r)}
		h.ServeDNS(r.Context(), w, req)
		if !w.written {
			http.Error(rw, "no DNS response", http.StatusServiceUnavailable)
		}
	})
}

func httpRemoteAddr(r *http.Request) net.Addr {
	addr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		return &net.TCPAddr{}
	}
	return addr
}

type httpWriter struct {
	rw      http.ResponseWriter
	remote  net.Addr
	written bool
}

func (w *httpWriter) WriteMsg(res *packet.DNSPacket) error {
	if w.written {
		return errors.New("server: response already written")
	}
	w.written = true
	// RFC 8484 §4.1: the DNS ID SHOULD be 0 in requests; replies echo it.
	data, _ := res.Pack(packet.MaxMessageSize)
	header := w.rw.Header()
	header.Set("Content-Type", dnsMessageType)
	header.Set("Content-Length", strconv.Itoa(len(data)))
	header.Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(MinTTL(res)), 10))
	_, err := w.rw.Write(data)
	return err
}

func (w *httpWriter) RemoteAddr() net.Addr { return w.remote }
func (w *httpWriter) Transport() Transport { return TransportDoH }

// MinTTL is the freshness lifetime of a response (RFC 8484 §5.1): the
// smallest TTL among answer and authority records, excluding OPT.
func MinTTL(res *packet.DNSPacket) uint32 {
	var min uint32
	found := false
	for _, section := range [][]packet.DNSResource{res.Answers, res.Authorities} {
		for _, r := range section {
			ttl := r.Header().TTL
			if soa, ok := r.(*packet.DNSResourceRecordSOA); ok && soa.Minimum < ttl {
				ttl = soa.Minimum
			}
			if !found || ttl < min {
				min, found = ttl, true
			}
		}
	}
	return min
}

func readDoHRequest(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		encoded := r.URL.Query().Get("dns")
		if encoded == "" {
			return nil, fmt.Errorf("missing dns query parameter")
		}
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("invalid dns query parameter")
		}
		if len(data) > packet.MaxMessageSize {
			return nil, fmt.Errorf("DNS message too large")
		}
		return data, nil
	case http.MethodPost:
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != dnsMessageType {
			return nil, fmt.Errorf("content type must be %s", dnsMessageType)
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, packet.MaxMessageSize+1))
		if err != nil {
			return nil, fmt.Errorf("read DNS message: %w", err)
		}
		if len(body) > packet.MaxMessageSize {
			return nil, fmt.Errorf("DNS message too large")
		}
		return body, nil
	default:
		return nil, &methodNotAllowedError{method: r.Method}
	}
}

type methodNotAllowedError struct{ method string }

func (e *methodNotAllowedError) Error() string { return "method not allowed: " + e.method }
