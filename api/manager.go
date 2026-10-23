// Package api is the HTTP management API (mounted at /api) and serves the
// web panel. All changes go through Manager, which treats the YAML config
// file as the single source of truth: a change is applied to a copy of the
// config, validated, applied to the running service, and only then written
// back to disk. Hand edits plus SIGHUP keep working the same way.
package api

import (
	"fmt"
	"sync"

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/engine"
)

// Manager serializes configuration changes.
type Manager struct {
	path string
	svc  *engine.Service

	mu  sync.Mutex
	cfg *config.Config
}

// NewManager manages cfg (as loaded from path) for svc. An empty path
// keeps changes in memory only.
func NewManager(path string, cfg *config.Config, svc *engine.Service) *Manager {
	return &Manager{path: path, svc: svc, cfg: cfg.Clone()}
}

// Service returns the running service.
func (m *Manager) Service() *engine.Service { return m.svc }

// Config returns a copy of the current configuration.
func (m *Manager) Config() *config.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Clone()
}

// Update applies fn to a copy of the configuration. The change takes effect
// only if fn succeeds, the result validates, the service accepts it, and
// (with a path) it is saved.
func (m *Manager) Update(fn func(*config.Config) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.cfg.Clone()
	if err := fn(next); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return &InvalidError{err}
	}
	if err := m.svc.Apply(next); err != nil {
		return &InvalidError{err}
	}
	if m.path != "" {
		if err := next.Save(m.path); err != nil {
			// The service already runs the new state; restore the old one so
			// memory and disk stay in agreement.
			if rollback := m.svc.Apply(m.cfg); rollback != nil {
				return fmt.Errorf("save config: %v (rollback failed: %v)", err, rollback)
			}
			return fmt.Errorf("save config: %w", err)
		}
	}
	m.cfg = next
	return nil
}

// Reload re-reads the config file and applies it (used for SIGHUP).
func (m *Manager) Reload() error {
	if m.path == "" {
		return fmt.Errorf("api: no config file to reload")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := config.Load(m.path)
	if err != nil {
		return err
	}
	if err := m.svc.Apply(cfg); err != nil {
		return err
	}
	m.cfg = cfg
	return nil
}

// InvalidError marks a change rejected because the resulting configuration
// is invalid; the API reports it as 400 rather than 500.
type InvalidError struct{ Err error }

func (e *InvalidError) Error() string { return e.Err.Error() }
func (e *InvalidError) Unwrap() error { return e.Err }

// NotFoundError marks a reference to something that does not exist.
type NotFoundError struct{ What string }

func (e *NotFoundError) Error() string { return e.What + " not found" }
