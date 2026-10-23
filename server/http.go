package server

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/lsongdev/dns-go/packet"
)

// DoHPath is the conventional RFC 8484 endpoint.
const DoHPath = "/dns-query"

const dnsMessageType = "application/dns-message"

// NewHTTPServer returns an http.Server with timeouts suited to DoH. h is
// usually a *DoHHandler, or a mux that mounts one next to other routes.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// ListenHTTP serves DoH over plain HTTP, for use behind a TLS-terminating
// reverse proxy.
func ListenHTTP(addr string, h Handler) error {
	return NewHTTPServer(addr, NewHTTPHandler(h)).ListenAndServe()
}

// ListenHTTPS serves DoH over HTTPS (HTTP/2 when the client supports it).
func ListenHTTPS(addr string, config *tls.Config, h Handler) error {
	ln, err := tls.Listen("tcp", addr, WithHTTP2(config))
	if err != nil {
		return err
	}
	return NewHTTPServer(addr, NewHTTPHandler(h)).Serve(ln)
}

// WithHTTP2 returns a copy of config that offers h2 via ALPN.
func WithHTTP2(config *tls.Config) *tls.Config {
	c := config.Clone()
	if len(c.NextProtos) == 0 {
		c.NextProtos = []string{"h2", "http/1.1"}
	}
	return c
}

// NewHTTPHandler returns a DoHHandler with default settings.
func NewHTTPHandler(h Handler) *DoHHandler {
	return &DoHHandler{Handler: h}
}

// DoHHandler serves RFC 8484 DNS-over-HTTPS at DoHPath and, with a client
// identifier, at DoHPath + "/{id}". Mount it for both patterns when using
// a mux. Other paths get 404.
type DoHHandler struct {
	Handler Handler
	// TrustedProxies are peers (e.g. a local nginx) whose X-Forwarded-For /
	// X-Real-IP headers name the real client. Requests from other peers
	// never have those headers honored.
	TrustedProxies []netip.Prefix
	// Hostname enables client IDs from TLS SNI ("{id}.<Hostname>") when this
	// process terminates TLS. A path ID takes precedence.
	Hostname string
}

func (d *DoHHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	clientID, ok := clientIDFromPath(r.URL.Path)
	if !ok {
		http.NotFound(rw, r)
		return
	}
	if clientID == "" && r.TLS != nil {
		clientID = clientIDFromSNI(r.TLS.ServerName, d.Hostname)
	}
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
	w := &httpWriter{rw: rw, remote: d.remoteAddr(r), clientID: clientID}
	d.Handler.ServeDNS(r.Context(), w, req)
	if !w.written {
		// The handler chose not to answer (e.g. access policy "drop").
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}

// clientIDFromPath accepts DoHPath and DoHPath/{id}.
func clientIDFromPath(path string) (string, bool) {
	if path == DoHPath {
		return "", true
	}
	id, ok := strings.CutPrefix(path, DoHPath+"/")
	if !ok || !ValidClientID(id) {
		return "", false
	}
	return strings.ToLower(id), true
}

// remoteAddr returns the client address, following X-Forwarded-For from
// right to left through trusted proxies only.
func (d *DoHHandler) remoteAddr(r *http.Request) netip.AddrPort {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.AddrPort{}
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if !d.trusted(peer.Addr()) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	if len(hops) == 0 {
		hops = r.Header.Values("X-Real-Ip")
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = netip.AddrPortFrom(addr.Unmap(), 0)
		if !d.trusted(client.Addr()) {
			break
		}
	}
	return client
}

func (d *DoHHandler) trusted(addr netip.Addr) bool {
	for _, p := range d.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

type httpWriter struct {
	rw       http.ResponseWriter
	remote   netip.AddrPort
	clientID string
	written  bool
}

func (w *httpWriter) WriteMsg(res *packet.DNSPacket) error {
	if w.written {
		return errors.New("server: response already written")
	}
	w.written = true
	data, _ := res.Pack(packet.MaxMessageSize)
	header := w.rw.Header()
	header.Set("Content-Type", dnsMessageType)
	header.Set("Content-Length", strconv.Itoa(len(data)))
	header.Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(MinTTL(res)), 10))
	_, err := w.rw.Write(data)
	return err
}

func (w *httpWriter) RemoteAddr() netip.AddrPort { return w.remote }
func (w *httpWriter) Transport() Transport       { return TransportDoH }
func (w *httpWriter) ClientID() string           { return w.clientID }

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
