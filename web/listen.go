package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"

	"github.com/lsongdev/dns-go/access"
	"github.com/lsongdev/dns-go/api"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/server"
)

// listener is one bound DNS socket and its serve loop.
type listener struct {
	spec config.ListenSpec

	mu     sync.Mutex
	closer io.Closer // nil when it failed to bind
	closed bool
	err    error
}

func (l *listener) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.closer != nil {
		l.closer.Close()
	}
}

func (l *listener) status() api.ListenerStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := api.ListenerStatus{Type: l.spec.Type, Addr: l.spec.Addr, TLS: l.spec.Secure()}
	if l.err != nil {
		s.Error = l.err.Error()
	}
	return s
}

// Start binds every configured listener. A listener that fails to bind is
// reported by the API's status (and in the returned error) while the
// others serve, so a taken port does not take the API down with it.
func (d *DNS) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.listeners != nil {
		return errors.New("dns: already started")
	}
	d.listeners = []*listener{}
	d.rebind(serving(d.Manager.Settings().Server))
	if d.Manager.Settings().Disabled {
		d.log.Info("dns: the server is turned off; no listener is bound")
	} else {
		d.warnOpenResolver()
	}
	var errs []error
	for _, l := range d.listeners {
		if s := l.status(); s.Error != "" {
			errs = append(errs, fmt.Errorf("listen %s %s: %s", s.Type, s.Addr, s.Error))
		}
	}
	return errors.Join(errs...)
}

// serving returns the listeners srv binds: none while it is turned off.
func serving(srv config.Server) []config.ListenSpec {
	if srv.Disabled {
		return nil
	}
	return srv.Listens
}

// rebind makes the running listeners match specs: unchanged ones keep
// serving, removed ones close, and new ones bind after the removed ones
// have released their ports. Callers hold d.mu.
func (d *DNS) rebind(specs []config.ListenSpec) {
	var kept []*listener
	next := []*listener{} // non-nil: started, even with nothing to bind
	for _, l := range d.listeners {
		if containsSpec(specs, l.spec) && l.status().Error == "" && !containsListener(kept, l.spec) {
			kept = append(kept, l)
			continue
		}
		l.close()
	}
	for _, spec := range specs {
		if i := indexListener(kept, spec); i >= 0 {
			next = append(next, kept[i])
			kept = append(kept[:i], kept[i+1:]...)
			continue
		}
		next = append(next, d.bind(spec))
	}
	d.listeners = next
}

// bind opens spec's socket and starts serving it. Errors are kept on the
// listener.
func (d *DNS) bind(spec config.ListenSpec) *listener {
	l := &listener{spec: spec}
	closer, serve, err := d.listen(spec)
	if err != nil {
		l.err = err
		d.log.Error("dns: listener did not start", "type", spec.Type, "addr", spec.Addr, "err", err)
		return l
	}
	l.closer = closer
	d.log.Info("dns: listening", "type", spec.Type, "addr", spec.Addr)
	go func() {
		err := serve()
		l.mu.Lock()
		defer l.mu.Unlock()
		if err != nil && !l.closed {
			l.err = err
			d.log.Error("dns: listener stopped", "type", spec.Type, "addr", spec.Addr, "err", err)
		}
	}()
	return l
}

// Listeners reports the DNS listeners and whether each is serving.
func (d *DNS) Listeners() []api.ListenerStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Manager.Settings().Disabled {
		return []api.ListenerStatus{}
	}
	if d.listeners == nil { // not started: report the configuration
		var out []api.ListenerStatus
		for _, spec := range d.Manager.Settings().Listens {
			out = append(out, api.ListenerStatus{Type: spec.Type, Addr: spec.Addr, TLS: spec.Secure(), Error: "not started"})
		}
		return out
	}
	out := make([]api.ListenerStatus, len(d.listeners))
	for i, l := range d.listeners {
		out[i] = l.status()
	}
	return out
}

// serveDNS answers with whichever service is running, so replacing the
// service (Reconfigure) needs no rebinding.
func (d *DNS) serveDNS(ctx context.Context, w server.ResponseWriter, req *packet.DNSPacket) {
	d.Manager.Service().Engine.ServeDNS(ctx, w, req)
}

// listen binds spec's socket immediately (so bind errors surface at once)
// and returns the closer and the blocking serve loop.
func (d *DNS) listen(spec config.ListenSpec) (io.Closer, func() error, error) {
	h := server.HandlerFunc(d.serveDNS)
	tlsConfig, err := d.certs.config(spec)
	if err != nil {
		return nil, nil, err
	}
	switch spec.Type {
	case "udp":
		conn, err := net.ListenPacket("udp", spec.Addr)
		if err != nil {
			return nil, nil, err
		}
		return conn, func() error { return closedOK((&server.UDPServer{Handler: h}).Serve(conn)) }, nil
	case "tcp", "dot":
		ln, err := net.Listen("tcp", spec.Addr)
		if err != nil {
			return nil, nil, err
		}
		s := &server.TCPServer{Handler: h, Hostname: spec.Hostname}
		if tlsConfig != nil {
			ln = tls.NewListener(ln, tlsConfig)
			s.Transport = server.TransportDoT
		}
		return ln, func() error { return closedOK(s.Serve(ln)) }, nil
	case "doh":
		proxies, err := access.ParseNetworks(spec.TrustedProxies)
		if err != nil {
			return nil, nil, err
		}
		ln, err := net.Listen("tcp", spec.Addr)
		if err != nil {
			return nil, nil, err
		}
		if tlsConfig != nil {
			ln = tls.NewListener(ln, server.WithHTTP2(tlsConfig))
		}
		doh := &server.DoHHandler{Handler: h, TrustedProxies: proxies, Hostname: spec.Hostname}
		srv := server.NewHTTPServer(spec.Addr, doh)
		return srv, func() error { return closedOK(srv.Serve(ln)) }, nil
	default:
		return nil, nil, fmt.Errorf("unknown listen type %q", spec.Type)
	}
}

// closedOK hides the error a serve loop returns because it was closed.
func closedOK(err error) error {
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// warnOpenResolver flags a forwarding resolver that answers anyone on a
// non-loopback UDP/TCP socket: such servers get abused for amplification.
func (d *DNS) warnOpenResolver() {
	cfg := d.Manager.Settings()
	if cfg.Mode != config.ModeForwarding || !d.Manager.Service().Access.AllowsEveryone() {
		return
	}
	for _, l := range cfg.Listens {
		if l.Type != "udp" && l.Type != "tcp" {
			continue
		}
		host, _, err := net.SplitHostPort(l.Addr)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			continue
		}
		d.log.Warn("dns: open resolver: access allows every address; restrict it or use client IDs over DoH/DoT", "type", l.Type, "addr", l.Addr)
	}
}

func containsSpec(specs []config.ListenSpec, spec config.ListenSpec) bool {
	for _, s := range specs {
		if reflect.DeepEqual(s, spec) {
			return true
		}
	}
	return false
}

func containsListener(ls []*listener, spec config.ListenSpec) bool {
	return indexListener(ls, spec) >= 0
}

func indexListener(ls []*listener, spec config.ListenSpec) int {
	for i, l := range ls {
		if reflect.DeepEqual(l.spec, spec) {
			return i
		}
	}
	return -1
}

// certStore serves TLS certificates for listeners: files, which Reload
// re-reads so renewed certificates take effect without dropping
// listeners, or the host's certificate source.
type certStore struct {
	source func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	mu    sync.RWMutex
	pairs map[[2]string]*tls.Certificate
}

// config returns the TLS configuration for spec, or nil for plain
// listeners.
func (s *certStore) config(spec config.ListenSpec) (*tls.Config, error) {
	switch {
	case spec.CertFile != "":
		return s.files(spec.CertFile, spec.KeyFile)
	case spec.TLS:
		if s.source == nil {
			return nil, errors.New("tls: no certificate source; set cert_file and key_file")
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.source}, nil
	default:
		return nil, nil
	}
}

// files loads a certificate pair and returns a configuration that always
// serves its latest loaded version.
func (s *certStore) files(certFile, keyFile string) (*tls.Config, error) {
	key := [2]string{certFile, keyFile}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.pairs == nil {
		s.pairs = make(map[[2]string]*tls.Certificate)
	}
	s.pairs[key] = &cert
	s.mu.Unlock()
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			return s.pairs[key], nil
		},
	}, nil
}

func (s *certStore) reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for key := range s.pairs {
		cert, err := tls.LoadX509KeyPair(key[0], key[1])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.pairs[key] = &cert
	}
	return errors.Join(errs...)
}

// TLSConfig returns a TLS configuration serving the certificate files,
// reloaded by Reload, for other servers of the host program (the
// standalone command's API listener).
func (d *DNS) TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	return d.certs.files(certFile, keyFile)
}
