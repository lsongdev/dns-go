//go:build !nosqlite && !mips && !mipsle && !mips64 && !mips64le

package store

import (
	"context"
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
	err = db.db.QueryRow(`SELECT name, ttl, type, data FROM records WHERE origin = 'home.lan' AND type = 'CNAME'`).Scan(&name, &ttl, &typ, &data)
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
	db.db.Exec("PRAGMA user_version = 99")
	db.Close()
	if _, _, err := OpenSQLite(path, config.Data{}); err == nil || !strings.Contains(err.Error(), "schema version 99") {
		t.Fatalf("want schema version error, got %v", err)
	}
}
