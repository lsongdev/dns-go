package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lsongdev/dns-go/config"
)

const configText = `# dns-go test config
mode: forwarding # keep me
listens:
  - {type: udp, addr: "127.0.0.1:0"}
upstreams:
  # primary upstream
  - {type: udp, addr: "1.1.1.1:53"}
domains:
  - domain: home.lan
    records: ["nas IN A 192.168.1.10"]
api:
  addr: "127.0.0.1:8080" # panel
`

func sample() config.Data {
	allow := []string{"private"}
	d := config.Data{
		Domains: []config.DomainSpec{
			{Domain: "home.lan", Kind: "static", Records: []string{"@ 300 IN A 192.168.1.1", "www 60 IN CNAME home.lan."}},
			{Domain: "", HostsFile: "/etc/hosts"},
			{Domain: "example.com", Kind: "transparent", Records: []string{`txt 300 IN TXT "hello \"world\""`}},
		},
		Filters: config.FiltersSpec{
			BlockMode: "nxdomain",
			Lists: []config.ListSpec{
				{Name: "ads", Kind: "block", URL: "https://lists.example/ads.txt", Refresh: config.Duration(3600e9)},
				{Name: "off", Kind: "allow", File: "/etc/allow.txt", Enabled: new(bool)},
			},
			Rules: []string{"||ads.example^", "@@||ok.example^"},
		},
		Access: config.AccessSpec{
			Allow:      &allow,
			Deny:       []string{"192.168.1.66"},
			DenyAction: "drop",
			Clients: []config.ClientSpec{
				{Name: "laptop", IDs: []string{"k3y", "other"}, Networks: []string{"192.168.1.20", "fd00::20"}},
				{Name: "tv", Networks: []string{"192.168.1.50"}},
			},
		},
	}
	d.ApplyDefaults()
	return d
}

func writeConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(configText), 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}

// backends returns a fresh instance of every Store implementation.
func backends(t *testing.T) map[string]Store {
	t.Helper()
	if !SQLiteAvailable {
		return map[string]Store{"config": NewConfigFile(writeConfig(t))}
	}
	db, _, err := OpenSQLite(filepath.Join(t.TempDir(), "db", "dns-go.db"), config.Data{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return map[string]Store{"config": NewConfigFile(writeConfig(t)), "sqlite": db}
}

func TestContract(t *testing.T) {
	ctx := context.Background()
	for name, st := range backends(t) {
		t.Run(name, func(t *testing.T) {
			want := sample()
			if err := st.Update(ctx, func(d *config.Data) error { *d = want.Clone(); return nil }); err != nil {
				t.Fatal(err)
			}
			got, err := st.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// sample() records are already canonical, so both backends must
			// return them unchanged.
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
			}

			// fn errors roll back.
			boom := errors.New("boom")
			err = st.Update(ctx, func(d *config.Data) error {
				d.Domains = nil
				return boom
			})
			if !errors.Is(err, boom) {
				t.Fatalf("Update error = %v", err)
			}
			if again, _ := st.Load(ctx); len(again.Domains) != 3 {
				t.Fatal("failed Update changed stored data")
			}

			// Updates see the latest data and can remove everything.
			if err := st.Update(ctx, func(d *config.Data) error {
				d.Domains = d.Domains[:1]
				d.Filters = config.FiltersSpec{}
				d.Access = config.AccessSpec{}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			got, _ = st.Load(ctx)
			if len(got.Domains) != 1 || got.Domains[0].Domain != "home.lan" || got.Filters.Lists != nil || got.Access.Allow != nil || got.Access.Clients != nil {
				t.Fatalf("after removal: %+v", got)
			}
		})
	}
}

func TestConfigFileKeepsOtherSectionsAndComments(t *testing.T) {
	path := writeConfig(t)
	st := NewConfigFile(path)
	err := st.Update(context.Background(), func(d *config.Data) error {
		d.Domains = append(d.Domains, config.DomainSpec{Domain: "lab.lan", Kind: "static"})
		d.Filters.Rules = []string{"||x.example^"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	text := string(raw)
	for _, want := range []string{"# dns-go test config", "# keep me", "# primary upstream", "# panel", "lab.lan", "||x.example^"} {
		if !strings.Contains(text, want) {
			t.Errorf("rewritten config lost %q:\n%s", want, text)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Errorf("permissions changed to %v", info.Mode().Perm())
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("rewritten config invalid: %v", err)
	}
	// Emptying a section removes its key.
	st.Update(context.Background(), func(d *config.Data) error { d.Filters = config.FiltersSpec{}; return nil })
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), "filters:") {
		t.Errorf("empty filters section kept:\n%s", raw)
	}
}
