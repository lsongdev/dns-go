package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/lsongdev/dns-go/access"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/engine"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/server"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	logQueries := flag.Bool("log-queries", false, "log every answered query")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	hooks := engine.Hooks{OnListUpdate: logListUpdate}
	if *logQueries {
		hooks.OnQuery = logQuery
	}
	svc, err := engine.NewService(cfg, hooks)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	defer svc.Close()

	certs := &certStore{}
	listeners := make([]io.Closer, 0, len(cfg.Listens))
	errCh := make(chan error, len(cfg.Listens))
	for _, l := range cfg.Listens {
		closer, serve, err := listen(l, svc.Engine, certs)
		if err != nil {
			log.Fatalf("listen %s %s: %v", l.Type, l.Addr, err)
		}
		listeners = append(listeners, closer)
		log.Printf("listening %s %s", l.Type, l.Addr)
		go func() { errCh <- serve() }()
	}
	log.Printf("mode %s: %d zone(s)", cfg.Mode, len(svc.Zones.List()))
	warnOpenResolver(cfg, svc)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		select {
		case err := <-errCh:
			if err != nil {
				log.Fatalf("listener: %v", err)
			}
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				reload(*cfgPath, svc, certs)
				continue
			}
			log.Printf("received %v, shutting down", sig)
			for _, c := range listeners {
				c.Close()
			}
			return
		}
	}
}

// warnOpenResolver flags a forwarding resolver that answers anyone on a
// non-loopback UDP/TCP socket: such servers get abused for amplification.
func warnOpenResolver(cfg *config.Config, svc *engine.Service) {
	if cfg.Mode != config.ModeForwarding || !svc.Access.AllowsEveryone() {
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
		log.Printf("WARNING: open resolver: access.allow admits every address on %s %s; restrict it or use client IDs over DoH/DoT", l.Type, l.Addr)
	}
}

// reload re-reads the config and certificates. Failures keep the running
// state, so a typo in the file never takes the server down.
func reload(path string, svc *engine.Service, certs *certStore) {
	cfg, err := config.Load(path)
	if err != nil {
		log.Printf("reload: %v", err)
		return
	}
	if err := svc.Apply(cfg); err != nil {
		log.Printf("reload: %v", err)
		return
	}
	if err := certs.reload(); err != nil {
		log.Printf("reload certificates: %v", err)
	}
	log.Printf("reload: %d zone(s)", len(svc.Zones.List()))
}

// listen binds l's socket immediately (so bind errors are fatal at startup)
// and returns the closer and the blocking serve loop.
func listen(l config.ListenSpec, h server.Handler, certs *certStore) (io.Closer, func() error, error) {
	var tlsConfig *tls.Config
	if l.CertFile != "" {
		cfg, err := certs.config(l.CertFile, l.KeyFile)
		if err != nil {
			return nil, nil, err
		}
		tlsConfig = cfg
	}
	switch l.Type {
	case "udp":
		conn, err := net.ListenPacket("udp", l.Addr)
		if err != nil {
			return nil, nil, err
		}
		return conn, func() error { return (&server.UDPServer{Handler: h}).Serve(conn) }, nil
	case "tcp", "dot":
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			return nil, nil, err
		}
		s := &server.TCPServer{Handler: h, Hostname: l.Hostname}
		if tlsConfig != nil {
			ln = tls.NewListener(ln, tlsConfig)
			s.Transport = server.TransportDoT
		}
		return ln, func() error { return s.Serve(ln) }, nil
	case "doh":
		ln, err := net.Listen("tcp", l.Addr)
		if err != nil {
			return nil, nil, err
		}
		if tlsConfig != nil {
			ln = tls.NewListener(ln, server.WithHTTP2(tlsConfig))
		}
		proxies, err := access.ParseNetworks(l.TrustedProxies)
		if err != nil {
			ln.Close()
			return nil, nil, err
		}
		doh := &server.DoHHandler{Handler: h, TrustedProxies: proxies, Hostname: l.Hostname}
		srv := server.NewHTTPServer(l.Addr, doh)
		return srv, func() error {
			if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		}, nil
	default:
		return nil, nil, fmt.Errorf("unknown listen type %q", l.Type)
	}
}

// certStore serves certificates that SIGHUP can reload, so renewed
// certificates take effect without dropping listeners.
type certStore struct {
	mu    sync.RWMutex
	pairs map[[2]string]*tls.Certificate
}

func (s *certStore) config(certFile, keyFile string) (*tls.Config, error) {
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

func logListUpdate(s filter.SourceStatus) {
	if s.Error != "" {
		log.Printf("filter list %s: %s", s.Name, s.Error)
		return
	}
	log.Printf("filter list %s: %d rules (%d skipped)", s.Name, s.Rules, s.Skipped)
}

func logQuery(ev engine.QueryEvent) {
	client := ev.Client.String()
	if ev.ClientName != "" {
		client += "(" + ev.ClientName + ")"
	}
	line := fmt.Sprintf("%s %s %s type=%d rcode=%d answers=%d source=%s %s",
		ev.Transport, client, ev.Name, ev.Type, ev.RCode, ev.Answers, ev.Source, ev.Duration.Round(time.Microsecond))
	if ev.Filter.Rule != "" {
		line += fmt.Sprintf(" filter=%s:%q", ev.Filter.List, ev.Filter.Rule)
	}
	if ev.Err != nil {
		line += " err=" + ev.Err.Error()
	}
	log.Print(line)
}
