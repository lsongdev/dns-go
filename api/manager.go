// Package api is the HTTP management API (mounted at /api) and serves the
// web panel. All changes go through Manager, which keeps three things in
// agreement: the store (config file or database), the running service, and
// its own cached copy of the data.
package api

import (
	"context"
	"fmt"
	"sync"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/engine"
	"github.com/lsongdev/dns-go/store"
)

// Manager serializes changes to the runtime data.
type Manager struct {
	cfg   *config.Config // process settings; fixed for the life of the process
	store store.Store
	svc   *engine.Service

	mu   sync.Mutex
	data config.Data // what the service is running
}

// NewManager loads the stored data into svc and returns a manager for it.
func NewManager(ctx context.Context, cfg *config.Config, st store.Store, svc *engine.Service) (*Manager, error) {
	m := &Manager{cfg: cfg, store: st, svc: svc}
	if err := m.Reload(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// Settings returns the process settings (listeners, upstreams, ...).
func (m *Manager) Settings() *config.Config { return m.cfg }

// Service returns the running service.
func (m *Manager) Service() *engine.Service { return m.svc }

// Data returns a copy of the running data.
func (m *Manager) Data() config.Data {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data.Clone()
}

// Update applies fn to the current data inside a store transaction. The
// change is applied to the running service before the transaction commits;
// if the service rejects it, nothing is stored, and if the commit fails,
// the service is put back to the previous data.
func (m *Manager) Update(ctx context.Context, fn func(*config.Data) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var applied *config.Data
	err := m.store.Update(ctx, func(d *config.Data) error {
		if err := fn(d); err != nil {
			return err
		}
		d.ApplyDefaults()
		if err := m.svc.Apply(*d); err != nil {
			return &InvalidError{err}
		}
		next := d.Clone()
		applied = &next
		return nil
	})
	if err != nil {
		if applied != nil {
			if rollback := m.svc.Apply(m.data); rollback != nil {
				return fmt.Errorf("%w (restoring previous data also failed: %v)", err, rollback)
			}
		}
		return err
	}
	m.data = *applied
	return nil
}

// Reload re-reads the store and applies it, e.g. after the config file was
// edited by hand (SIGHUP). File-backed zones and lists are re-read too.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.store.Load(ctx)
	if err != nil {
		return err
	}
	if err := m.svc.Apply(d); err != nil {
		return err
	}
	m.data = d
	return nil
}

// InvalidError marks a change rejected because the resulting data is
// invalid; the API reports it as 400 rather than 500.
type InvalidError struct{ Err error }

func (e *InvalidError) Error() string { return e.Err.Error() }
func (e *InvalidError) Unwrap() error { return e.Err }

// NotFoundError marks a reference to something that does not exist.
type NotFoundError struct{ What string }

func (e *NotFoundError) Error() string { return e.What + " not found" }
