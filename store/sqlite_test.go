//go:build !nosqlite && !mips && !mipsle && !mips64 && !mips64le

package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lsongdev/dns-go/config"
)

func TestSQLiteSeedsOnceAndStoresRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-go.db")
	seed := sample()
	db, seeded, err := OpenSQLite(path, seed)
	if err != nil || !seeded {
		t.Fatalf("first open: seeded=%v err=%v", seeded, err)
	}
	var name, typ, data string
	var ttl int
	err = db.db.QueryRow(`SELECT name, ttl, type, data FROM dns_records WHERE origin = 'home.lan' AND type = 'CNAME'`).Scan(&name, &ttl, &typ, &data)
	if err != nil || name != "www" || ttl != 60 || data != "home.lan." {
		t.Fatalf("record row = %q %d %q %q (%v)", name, ttl, typ, data, err)
	}
	db.Close()

	db, seeded, err = OpenSQLite(path, config.Data{Domains: []config.DomainSpec{{Domain: "ignored.lan"}}})
	if err != nil || seeded {
		t.Fatalf("second open: seeded=%v err=%v", seeded, err)
	}
	defer db.Close()
	got, _ := db.Load(context.Background())
	if len(got.Domains) != 3 || got.Domains[0].Domain != "home.lan" {
		t.Fatalf("existing database must not be reseeded: %+v", got.Domains)
	}

	// Constraints in the schema back up validation: client IDs are unique
	// regardless of case.
	err = db.Update(context.Background(), func(d *config.Data) error {
		d.Access.Clients = append(d.Access.Clients, config.ClientSpec{Name: "dup", IDs: []string{"K3Y"}})
		return nil
	})
	if err == nil {
		t.Fatal("duplicate client id accepted")
	}
	if got, _ := db.Load(context.Background()); len(got.Access.Clients) != 2 {
		t.Fatal("failed update left partial rows")
	}
}

func TestSQLiteRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-go.db")
	db, _, err := OpenSQLite(path, config.Data{})
	if err != nil {
		t.Fatal(err)
	}
	db.db.Exec("UPDATE dns_schema SET version = 99")
	db.Close()
	if _, _, err := OpenSQLite(path, config.Data{}); err == nil || !strings.Contains(err.Error(), "schema version 99") {
		t.Fatalf("want schema version error, got %v", err)
	}
}

// A database created by an earlier dns-go (unprefixed tables, PRAGMA
// user_version 1) is upgraded in place, keeping its data.
func TestSQLiteUpgradesUnprefixedTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns-go.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.ReplaceAll(migrations[0], "dns_", "")
	for _, stmt := range []string{legacy,
		`INSERT INTO zones VALUES ('home.lan', 'static', '', '', 0, '2026-01-01T00:00:00Z')`,
		`INSERT INTO records (origin, position, name, ttl, type, data) VALUES ('home.lan', 0, 'nas', 300, 'A', '192.168.1.10')`,
		`PRAGMA user_version = 1`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, seeded, err := OpenSQLite(path, sample())
	if err != nil || seeded {
		t.Fatalf("open: seeded=%v err=%v", seeded, err)
	}
	defer s.Close()
	got, err := s.Load(context.Background())
	if err != nil || len(got.Domains) != 1 || got.Domains[0].Records[0] != "nas 300 IN A 192.168.1.10" {
		t.Fatalf("upgraded data = %+v (%v)", got.Domains, err)
	}
	// Foreign keys follow the renamed tables.
	if err := s.Update(context.Background(), func(d *config.Data) error { d.Domains = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM dns_records`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d records left after deleting their zone", n)
	}
}

// A shared database keeps dns-go's tables next to other programs' tables,
// and stays open when the store closes.
func TestSQLiteSharedDatabase(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "shared.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE zones (other TEXT)`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, seeded, err := NewSQLite(ctx, db, sample())
	if err != nil || !seeded {
		t.Fatalf("new: seeded=%v err=%v", seeded, err)
	}
	if _, ok, err := s.LoadServer(ctx); ok || err != nil {
		t.Fatalf("server settings before saving: ok=%v err=%v", ok, err)
	}
	srv := config.Server{Mode: "forwarding", Listens: []config.ListenSpec{{Type: "udp", Addr: ":53"}}, Upstreams: []config.UpstreamSpec{{Type: "udp", Addr: "1.1.1.1:53"}}}
	if err := s.SaveServer(ctx, srv); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("closing the store closed the shared database: %v", err)
	}
	s, seeded, err = NewSQLite(ctx, db, config.Data{})
	if err != nil || seeded {
		t.Fatalf("reopen: seeded=%v err=%v", seeded, err)
	}
	got, ok, err := s.LoadServer(ctx)
	if err != nil || !ok || got.Listens[0].Addr != ":53" || got.Upstreams[0].Timeout == 0 {
		t.Fatalf("server settings = %+v ok=%v err=%v", got, ok, err)
	}
	if d, _ := s.Load(ctx); len(d.Domains) != 3 {
		t.Fatalf("data = %+v", d.Domains)
	}
}
