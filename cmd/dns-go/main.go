package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/server"
	"github.com/lsongdev/dns-go/store"
	"github.com/lsongdev/dns-go/web"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version string

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	logQueries := flag.Bool("log-queries", false, "log every answered query")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(versionString())
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	opened, err := store.Open(cfg, *cfgPath)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}
	switch {
	case opened.Seeded:
		log.Printf("storage: created %s from the config file's data sections", cfg.Storage.Path)
	case cfg.Storage.Type == config.StorageSQLite && hasData(cfg.Data):
		log.Printf("storage: %s is authoritative; domains/filters/access in %s are ignored", cfg.Storage.Path, *cfgPath)
	}
	// The server settings live in the config file whichever storage holds
	// the data; the panel's changes are written back to it.
	dns, err := web.Open(context.Background(), cfg, opened.Store, store.NewConfigFile(*cfgPath), web.Options{
		Version: versionString(), Logger: slog.Default(), LogQueries: *logQueries,
	})
	if err != nil {
		log.Fatalf("data: %v", err)
	}
	defer dns.Close()
	if err := dns.Start(); err != nil {
		log.Fatal(err)
	}

	errCh := make(chan error, 1)
	var apiServer *http.Server
	if cfg.API.Addr != "" {
		apiServer, err = serveAPI(cfg.API, dns, errCh)
		if err != nil {
			log.Fatalf("api %s: %v", cfg.API.Addr, err)
		}
	}
	log.Printf("mode %s, storage %s: %d zone(s)", cfg.Mode, cfg.Storage.Type, len(dns.Manager.Service().Zones.List()))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		select {
		case err := <-errCh:
			log.Fatalf("api: %v", err)
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				reload(dns)
				continue
			}
			log.Printf("received %v, shutting down", sig)
			if apiServer != nil {
				apiServer.Close()
			}
			return
		}
	}
}

func versionString() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Version
	}
	return "devel"
}

func hasData(d config.Data) bool {
	return len(d.Domains) > 0 || len(d.Filters.Lists) > 0 || len(d.Filters.Rules) > 0 || len(d.Access.Clients) > 0 || d.Access.Allow != nil
}

// reload re-reads the stored data and certificates. Failures keep the
// running state, so a typo in the file never takes the server down.
func reload(dns *web.DNS) {
	if err := dns.Reload(context.Background()); err != nil {
		log.Printf("reload: %v", err)
		return
	}
	log.Printf("reload: %d zone(s)", len(dns.Manager.Service().Zones.List()))
}

// serveAPI serves the management API and web panel. Changing api settings
// needs a restart.
func serveAPI(spec config.APISpec, dns *web.DNS, errCh chan<- error) (*http.Server, error) {
	ln, err := net.Listen("tcp", spec.Addr)
	if err != nil {
		return nil, err
	}
	scheme := "http"
	if spec.CertFile != "" {
		tlsConfig, err := dns.TLSConfig(spec.CertFile, spec.KeyFile)
		if err != nil {
			ln.Close()
			return nil, err
		}
		ln = tls.NewListener(ln, server.WithHTTP2(tlsConfig))
		scheme = "https"
	}
	srv := &http.Server{
		Handler:           dns.Standalone(spec.Token),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("api and panel on %s://%s", scheme, spec.Addr)
	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	return srv, nil
}
