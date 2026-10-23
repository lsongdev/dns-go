package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure Go, no cgo)

	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/zone"
)

const schemaVersion = 1

const schema = `
CREATE TABLE zones (
	origin     TEXT PRIMARY KEY,           -- canonical, no trailing dot; '' is the root
	kind       TEXT NOT NULL CHECK (kind IN ('static', 'transparent')),
	zone_file  TEXT NOT NULL DEFAULT '',
	hosts_file TEXT NOT NULL DEFAULT '',
	position   INTEGER NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE records (
	id       INTEGER PRIMARY KEY,
	origin   TEXT NOT NULL REFERENCES zones (origin) ON DELETE CASCADE ON UPDATE CASCADE,
	position INTEGER NOT NULL,
	name     TEXT NOT NULL,                -- relative to origin, '@' for the apex
	ttl      INTEGER NOT NULL,
	type     TEXT NOT NULL,
	data     TEXT NOT NULL                 -- RDATA in presentation format
);
CREATE INDEX records_by_zone ON records (origin, position);
CREATE INDEX records_by_name ON records (name, type);
CREATE TABLE filter_lists (
	name     TEXT PRIMARY KEY,
	kind     TEXT NOT NULL CHECK (kind IN ('block', 'allow')),
	url      TEXT NOT NULL DEFAULT '',
	file     TEXT NOT NULL DEFAULT '',
	enabled  INTEGER NOT NULL,
	refresh  TEXT NOT NULL DEFAULT '',     -- Go duration, '' for the default
	position INTEGER NOT NULL
);
CREATE TABLE filter_rules (
	position INTEGER PRIMARY KEY,
	rule     TEXT NOT NULL
);
CREATE TABLE clients (
	name     TEXT PRIMARY KEY,
	position INTEGER NOT NULL
);
CREATE TABLE client_ids (
	id     TEXT PRIMARY KEY COLLATE NOCASE,
	client TEXT NOT NULL REFERENCES clients (name) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE client_networks (
	client   TEXT NOT NULL REFERENCES clients (name) ON DELETE CASCADE ON UPDATE CASCADE,
	network  TEXT NOT NULL,
	position INTEGER NOT NULL,
	PRIMARY KEY (client, position)
);
CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL                    -- JSON
);
`

// SQLite stores config.Data in a SQLite database.
type SQLite struct {
	db *sql.DB
	mu sync.Mutex
}

// OpenSQLite opens (creating if needed) the database at path. A new
// database is seeded with seed, normally the config file's data sections;
// seeded reports whether that happened.
func OpenSQLite(path string, seed config.Data) (s *SQLite, seeded bool, err error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, false, err
		}
	}
	// The database holds client IDs, which are secrets: create it private.
	// SQLite gives its -wal and -shm files the same permissions.
	if f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600); err == nil {
		f.Close()
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, false, err
	}
	// One connection: writes are rare and serialized anyway, and it keeps
	// pragmas and transactions simple.
	db.SetMaxOpenConns(1)
	s = &SQLite{db: db}
	defer func() {
		if err != nil {
			db.Close()
		}
	}()

	ctx := context.Background()
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, false, fmt.Errorf("store: open %s: %w", path, err)
	}
	switch version {
	case schemaVersion:
		return s, false, nil
	case 0:
	default:
		return nil, false, fmt.Errorf("store: %s has schema version %d; this build supports %d", path, version, schemaVersion)
	}
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		seed.ApplyDefaults()
		if err := write(ctx, tx, config.Data{}, seed); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))
		return err
	})
	if err != nil {
		return nil, false, fmt.Errorf("store: initialize %s: %w", path, err)
	}
	return s, true, nil
}

func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) Load(ctx context.Context) (config.Data, error) {
	var d config.Data
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var err error
		d, err = read(ctx, tx)
		return err
	})
	return d, err
}

func (s *SQLite) Update(ctx context.Context, fn func(*config.Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inTx(ctx, func(tx *sql.Tx) error {
		old, err := read(ctx, tx)
		if err != nil {
			return err
		}
		next := old.Clone()
		if err := fn(&next); err != nil {
			return err
		}
		return write(ctx, tx, old, next)
	})
}

func (s *SQLite) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- reading ----

func read(ctx context.Context, tx *sql.Tx) (config.Data, error) {
	var d config.Data
	var err error
	if d.Domains, err = readZones(ctx, tx); err != nil {
		return d, err
	}
	if d.Filters, err = readFilters(ctx, tx); err != nil {
		return d, err
	}
	if d.Access, err = readAccess(ctx, tx); err != nil {
		return d, err
	}
	d.ApplyDefaults()
	return d, nil
}

func readZones(ctx context.Context, tx *sql.Tx) ([]config.DomainSpec, error) {
	rows, err := tx.QueryContext(ctx, `SELECT origin, kind, zone_file, hosts_file FROM zones ORDER BY position`)
	if err != nil {
		return nil, err
	}
	var zones []config.DomainSpec
	index := map[string]int{}
	for rows.Next() {
		var z config.DomainSpec
		if err := rows.Scan(&z.Domain, &z.Kind, &z.ZoneFile, &z.HostsFile); err != nil {
			rows.Close()
			return nil, err
		}
		index[z.Domain] = len(zones)
		zones = append(zones, z)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	recs, err := tx.QueryContext(ctx, `SELECT origin, name, ttl, type, data FROM records ORDER BY origin, position`)
	if err != nil {
		return nil, err
	}
	defer recs.Close()
	for recs.Next() {
		var origin string
		var r zone.RecordText
		if err := recs.Scan(&origin, &r.Name, &r.TTL, &r.Type, &r.Data); err != nil {
			return nil, err
		}
		i := index[origin]
		zones[i].Records = append(zones[i].Records, r.String())
	}
	return zones, recs.Err()
}

func readFilters(ctx context.Context, tx *sql.Tx) (config.FiltersSpec, error) {
	var f config.FiltersSpec
	if err := getSetting(ctx, tx, "filters.block_mode", &f.BlockMode); err != nil {
		return f, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT name, kind, url, file, enabled, refresh FROM filter_lists ORDER BY position`)
	if err != nil {
		return f, err
	}
	for rows.Next() {
		var l config.ListSpec
		var enabled bool
		var refresh string
		if err := rows.Scan(&l.Name, &l.Kind, &l.URL, &l.File, &enabled, &refresh); err != nil {
			rows.Close()
			return f, err
		}
		if !enabled {
			l.Enabled = &enabled
		}
		if refresh != "" {
			d, err := time.ParseDuration(refresh)
			if err != nil {
				rows.Close()
				return f, fmt.Errorf("filter list %s: refresh %q: %w", l.Name, refresh, err)
			}
			l.Refresh = config.Duration(d)
		}
		f.Lists = append(f.Lists, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return f, err
	}
	rules, err := tx.QueryContext(ctx, `SELECT rule FROM filter_rules ORDER BY position`)
	if err != nil {
		return f, err
	}
	defer rules.Close()
	for rules.Next() {
		var r string
		if err := rules.Scan(&r); err != nil {
			return f, err
		}
		f.Rules = append(f.Rules, r)
	}
	return f, rules.Err()
}

func readAccess(ctx context.Context, tx *sql.Tx) (config.AccessSpec, error) {
	var a config.AccessSpec
	for key, dst := range map[string]any{"access.allow": &a.Allow, "access.deny": &a.Deny, "access.deny_action": &a.DenyAction} {
		if err := getSetting(ctx, tx, key, dst); err != nil {
			return a, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT name FROM clients ORDER BY position`)
	if err != nil {
		return a, err
	}
	index := map[string]int{}
	for rows.Next() {
		var c config.ClientSpec
		if err := rows.Scan(&c.Name); err != nil {
			rows.Close()
			return a, err
		}
		index[c.Name] = len(a.Clients)
		a.Clients = append(a.Clients, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return a, err
	}
	ids, err := tx.QueryContext(ctx, `SELECT client, id FROM client_ids ORDER BY rowid`)
	if err != nil {
		return a, err
	}
	for ids.Next() {
		var client, id string
		if err := ids.Scan(&client, &id); err != nil {
			ids.Close()
			return a, err
		}
		a.Clients[index[client]].IDs = append(a.Clients[index[client]].IDs, id)
	}
	ids.Close()
	if err := ids.Err(); err != nil {
		return a, err
	}
	nets, err := tx.QueryContext(ctx, `SELECT client, network FROM client_networks ORDER BY client, position`)
	if err != nil {
		return a, err
	}
	defer nets.Close()
	for nets.Next() {
		var client, network string
		if err := nets.Scan(&client, &network); err != nil {
			return a, err
		}
		a.Clients[index[client]].Networks = append(a.Clients[index[client]].Networks, network)
	}
	return a, nets.Err()
}

func getSetting(ctx context.Context, tx *sql.Tx, key string, dst any) error {
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(raw), dst)
}

// ---- writing ----

// write persists next, touching only what differs from old.
func write(ctx context.Context, tx *sql.Tx, old, next config.Data) error {
	if !reflect.DeepEqual(old.Domains, next.Domains) {
		if err := writeZones(ctx, tx, old.Domains, next.Domains); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(old.Filters, next.Filters) {
		if err := writeFilters(ctx, tx, next.Filters); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(old.Access, next.Access) {
		if err := writeAccess(ctx, tx, next.Access); err != nil {
			return err
		}
	}
	return nil
}

func writeZones(ctx context.Context, tx *sql.Tx, old, next []config.DomainSpec) error {
	before := map[string]config.DomainSpec{}
	for _, z := range old {
		before[zone.CanonicalName(z.Domain)] = z
	}
	keep := map[string]bool{}
	now := time.Now().UTC().Format(time.RFC3339)
	for pos, z := range next {
		origin := zone.CanonicalName(z.Domain)
		keep[origin] = true
		prev, existed := before[origin]
		if existed && reflect.DeepEqual(prev, z) {
			if _, err := tx.ExecContext(ctx, `UPDATE zones SET position = ? WHERE origin = ?`, pos, origin); err != nil {
				return err
			}
			continue
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO zones (origin, kind, zone_file, hosts_file, position, updated_at) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (origin) DO UPDATE SET kind = excluded.kind, zone_file = excluded.zone_file,
				hosts_file = excluded.hosts_file, position = excluded.position, updated_at = excluded.updated_at`,
			origin, z.Kind, z.ZoneFile, z.HostsFile, pos, now)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM records WHERE origin = ?`, origin); err != nil {
			return err
		}
		for i, line := range z.Records {
			r, err := zone.ParseRecordText(originName(origin), line)
			if err != nil {
				return fmt.Errorf("zone %s: %q: %w", originName(origin), line, err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO records (origin, position, name, ttl, type, data) VALUES (?, ?, ?, ?, ?, ?)`,
				origin, i, r.Name, r.TTL, r.Type, r.Data); err != nil {
				return err
			}
		}
	}
	for origin := range before {
		if !keep[origin] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM zones WHERE origin = ?`, origin); err != nil {
				return err
			}
		}
	}
	return nil
}

func originName(origin string) string {
	if origin == "" {
		return "."
	}
	return origin
}

func writeFilters(ctx context.Context, tx *sql.Tx, f config.FiltersSpec) error {
	if err := setSetting(ctx, tx, "filters.block_mode", f.BlockMode); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM filter_lists`); err != nil {
		return err
	}
	for i, l := range f.Lists {
		refresh := ""
		if l.Refresh != 0 {
			refresh = l.Refresh.Duration().String()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO filter_lists (name, kind, url, file, enabled, refresh, position) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			l.Name, l.Kind, l.URL, l.File, l.IsEnabled(), refresh, i); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM filter_rules`); err != nil {
		return err
	}
	for i, r := range f.Rules {
		if _, err := tx.ExecContext(ctx, `INSERT INTO filter_rules (position, rule) VALUES (?, ?)`, i, r); err != nil {
			return err
		}
	}
	return nil
}

func writeAccess(ctx context.Context, tx *sql.Tx, a config.AccessSpec) error {
	for key, v := range map[string]any{"access.allow": a.Allow, "access.deny": a.Deny, "access.deny_action": a.DenyAction} {
		if err := setSetting(ctx, tx, key, v); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM clients`); err != nil {
		return err
	}
	for i, c := range a.Clients {
		if _, err := tx.ExecContext(ctx, `INSERT INTO clients (name, position) VALUES (?, ?)`, c.Name, i); err != nil {
			return err
		}
		for _, id := range c.IDs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO client_ids (id, client) VALUES (?, ?)`, id, c.Name); err != nil {
				return fmt.Errorf("client %s: id %s: %w", c.Name, id, err)
			}
		}
		for j, n := range c.Networks {
			if _, err := tx.ExecContext(ctx, `INSERT INTO client_networks (client, network, position) VALUES (?, ?, ?)`, c.Name, n, j); err != nil {
				return err
			}
		}
	}
	return nil
}

func setSetting(ctx context.Context, tx *sql.Tx, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, string(raw))
	return err
}
