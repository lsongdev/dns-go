//go:build nosqlite || mips || mipsle || mips64 || mips64le

package store

import (
	"context"
	"errors"

	"github.com/lsongdev/dns-go/config"
)

// SQLiteAvailable reports whether this binary includes the SQLite backend.
// The pure-Go driver does not support MIPS, and -tags nosqlite drops it to
// shrink the binary; storage.type "config" works everywhere.
const SQLiteAvailable = false

var errNoSQLite = errors.New(`store: this build has no SQLite support (MIPS or -tags nosqlite); use storage.type "config"`)

// SQLite is unavailable in this build.
type SQLite struct{}

func OpenSQLite(path string, seed config.Data) (*SQLite, bool, error) { return nil, false, errNoSQLite }

func (*SQLite) Load(context.Context) (config.Data, error)              { return config.Data{}, errNoSQLite }
func (*SQLite) Update(context.Context, func(*config.Data) error) error { return errNoSQLite }
func (*SQLite) Close() error                                           { return nil }
