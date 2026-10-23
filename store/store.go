// Package store persists config.Data, the runtime-managed configuration
// (zones, filters, access). The rest of the program sees only config.Data;
// where it lives is a deployment choice:
//
//   - ConfigFile keeps it in the YAML config file itself (the default);
//   - SQLite keeps it in a database, seeded once from the config file.
package store

import (
	"context"
	"fmt"

	"github.com/lsongdev/dns-go/config"
)

// Store loads and transactionally updates config.Data.
type Store interface {
	// Load returns the current data with defaults applied.
	Load(ctx context.Context) (config.Data, error)
	// Update runs fn on a copy of the current data and persists the result
	// if fn returns nil. Updates are serialized; fn sees the latest data.
	Update(ctx context.Context, fn func(*config.Data) error) error
	Close() error
}

// Opened describes how a store was opened, for startup logging.
type Opened struct {
	Store  Store
	Seeded bool // a new database was initialized from the config file
}

// Open returns the store selected by cfg. configPath is the file cfg was
// loaded from.
func Open(cfg *config.Config, configPath string) (Opened, error) {
	switch cfg.Storage.Type {
	case config.StorageConfig, "":
		return Opened{Store: NewConfigFile(configPath)}, nil
	case config.StorageSQLite:
		s, seeded, err := OpenSQLite(cfg.Storage.Path, cfg.Data)
		if err != nil {
			return Opened{}, err
		}
		return Opened{Store: s, Seeded: seeded}, nil
	default:
		return Opened{}, fmt.Errorf("store: unknown storage type %q", cfg.Storage.Type)
	}
}
