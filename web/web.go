// Package web assembles dns-go as a panel module: the resolver with its
// listeners, the management API, and the browser UI (native ES modules in
// ui/, no build step).
//
// A DNS value satisfies the panel module contract without depending on any
// panel: Handler serves the API with relative routes and Assets holds the
// UI with manifest.json at its root. The standalone command and a panel
// build it the same way; only where the settings come from differs (a
// config file, or a database the panel shares).
package web

import (
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/lsongdev/dns-go/api"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/engine"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/store"
)

//go:embed ui
var embedded embed.FS

// UI is the module's browser assets; manifest.json describes them.
var UI = func() fs.FS {
	sub, err := fs.Sub(embedded, "ui")
	if err != nil {
		panic(err) // the embed directive guarantees the directory exists
	}
	return sub
}()

// Options configures the module.
type Options struct {
	// Server is stored and used when the database holds no server settings
	// yet (New only; Open takes them from the config).
	Server config.Server
	// DataDir holds downloaded filter lists (New only).
	DataDir string
	// Certificates serves TLS for listeners with "tls: true", typically
	// from a certificate manager. Without it such listeners fail to start.
	Certificates func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Version      string
	Logger       *slog.Logger
	// LogQueries logs every answered query at info level.
	LogQueries bool
}

// DNS is an assembled DNS server.
type DNS struct {
	Manager *api.Manager
	Stats   *api.Stats

	opts    Options
	log     *slog.Logger
	servers store.ServerStore // nil: settings are read-only
	data    store.Store
	certs   *certStore
	handler http.Handler

	mu        sync.Mutex // serializes Start, Reconfigure and Close
	listeners []*listener
}

// New migrates dns-go's tables in db (prefixed "dns_", so db may be shared
// with other modules) and assembles the server from what they hold. On
// first use the server settings are opts.Server. The caller owns db; call
// Start to bind the listeners.
func New(ctx context.Context, db *sql.DB, opts Options) (*DNS, error) {
	st, _, err := store.NewSQLite(ctx, db, config.Data{})
	if err != nil {
		return nil, err
	}
	srv, ok, err := st.LoadServer(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		srv = opts.Server.Clone()
		srv.ApplyDefaults()
		if err := srv.Validate(); err != nil {
			return nil, fmt.Errorf("initial server settings: %w", err)
		}
		if err := st.SaveServer(ctx, srv); err != nil {
			return nil, err
		}
	}
	cfg := &config.Config{Server: srv, DataDir: opts.DataDir, Storage: config.StorageSpec{Type: config.StorageSQLite}}
	return Open(ctx, cfg, st, st, opts)
}

// Open assembles the server from cfg's server settings and data directory,
// with the runtime data in data. servers, if not nil, stores settings
// changed through the API; otherwise they are read-only. Open takes
// ownership of data. Call Start to bind the listeners.
func Open(ctx context.Context, cfg *config.Config, data store.Store, servers store.ServerStore, opts Options) (*DNS, error) {
	d := &DNS{
		Stats: api.NewStats(), opts: opts, log: opts.Logger,
		servers: servers, data: data, certs: &certStore{source: opts.Certificates},
	}
	if d.log == nil {
		d.log = slog.Default()
	}
	svc, err := engine.NewService(cfg, d.hooks())
	if err != nil {
		return nil, err
	}
	if d.Manager, err = api.NewManager(ctx, cfg, data, svc); err != nil {
		svc.Close()
		return nil, err
	}
	apiOpts := api.Options{Version: opts.Version, Listeners: d.Listeners}
	if servers != nil {
		apiOpts.Reconfigure = d.Reconfigure
	}
	d.handler = api.NewHandler(d.Manager, d.Stats, apiOpts)
	return d, nil
}

// Handler serves the module's API with relative routes.
func (d *DNS) Handler() http.Handler { return d.handler }

// Assets returns the browser UI; manifest.json is at its root.
func (d *DNS) Assets() fs.FS { return UI }

// Settings returns the running server settings.
func (d *DNS) Settings() config.Server { return d.Manager.Settings().Server.Clone() }

// Reconfigure applies new server settings: it rebuilds the resolver with
// the current data, rebinds the listeners that changed and stores the
// settings. Listeners that fail to bind are reported by the API's status;
// they do not undo the change.
func (d *DNS) Reconfigure(ctx context.Context, srv config.Server) error {
	if d.servers == nil {
		return errors.New("the server settings are read-only")
	}
	srv.ApplyDefaults()
	if err := srv.Validate(); err != nil {
		return &api.InvalidError{Err: err}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	prev := d.Manager.Settings()
	next := *prev
	next.Server = srv.Clone()
	svc, err := engine.NewService(&next, d.hooks())
	if err != nil {
		return &api.InvalidError{Err: err}
	}
	old, err := d.Manager.Replace(&next, svc)
	if err != nil {
		svc.Close()
		return err
	}
	if err := d.servers.SaveServer(ctx, srv); err != nil {
		d.Manager.Replace(prev, old)
		svc.Close()
		return err
	}
	old.Close()
	if d.listeners != nil { // started: bring the listeners in line
		d.rebind(serving(srv))
	}
	d.log.Info("dns: server settings changed", "enabled", !srv.Disabled, "mode", srv.Mode, "listeners", len(srv.Listens), "upstreams", len(srv.Upstreams))
	return nil
}

// Reload re-reads the stored data and the certificate files, e.g. after
// the config file was edited by hand (SIGHUP). Failures keep the running
// state.
func (d *DNS) Reload(ctx context.Context) error {
	if err := d.Manager.Reload(ctx); err != nil {
		return err
	}
	return d.certs.reload()
}

// Close stops the listeners and background work, and closes the data
// store. A database passed to New belongs to the caller and stays open.
func (d *DNS) Close() error {
	d.mu.Lock()
	for _, l := range d.listeners {
		l.close()
	}
	d.listeners = nil
	d.mu.Unlock()
	return errors.Join(d.Manager.Service().Close(), d.data.Close())
}

func (d *DNS) hooks() engine.Hooks {
	return engine.Hooks{
		OnListUpdate: func(s filter.SourceStatus) {
			if s.Error != "" {
				d.log.Warn("dns: filter list update failed", "list", s.Name, "err", s.Error)
				return
			}
			d.log.Info("dns: filter list updated", "list", s.Name, "rules", s.Rules, "skipped", s.Skipped)
		},
		OnQuery: func(ev engine.QueryEvent) {
			d.Stats.Record(ev)
			if d.opts.LogQueries {
				d.logQuery(ev)
			}
		},
	}
}

func (d *DNS) logQuery(ev engine.QueryEvent) {
	attrs := []any{
		"transport", ev.Transport, "client", ev.Client.String(), "name", ev.Name, "type", ev.Type,
		"rcode", ev.RCode, "answers", ev.Answers, "source", ev.Source, "took", ev.Duration.Round(time.Microsecond),
	}
	if ev.ClientName != "" {
		attrs = append(attrs, "client_name", ev.ClientName)
	}
	if ev.Filter.Rule != "" {
		attrs = append(attrs, "filter_list", ev.Filter.List, "filter_rule", ev.Filter.Rule)
	}
	if ev.Err != nil {
		attrs = append(attrs, "err", ev.Err)
	}
	d.log.Info("dns: query", attrs...)
}
