package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lsongdev/dns-go/access"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/engine"
	"github.com/lsongdev/dns-go/filter"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/store"
)

type fixture struct {
	t       *testing.T
	h       *Handler
	path    string
	dir     string
	svc     *engine.Service
	storage string
	dbPath  string
}

const baseConfig = `
listens: [{type: udp, addr: "127.0.0.1:0"}]
upstreams: [{type: udp, addr: "127.0.0.1:1", timeout: 100ms}]
cache: {enabled: true}
domains:
  - domain: home.lan
    records: ["nas 300 IN A 192.168.1.10"]
  - domain: file.lan
    zone_file: %s
`

// forEachStore runs fn against every storage backend: the API must behave
// the same whichever one holds the data.
func forEachStore(t *testing.T, fn func(t *testing.T, f *fixture)) {
	for _, storage := range []string{config.StorageConfig, config.StorageSQLite} {
		t.Run(storage, func(t *testing.T) {
			if storage == config.StorageSQLite && !store.SQLiteAvailable {
				t.Skip("built without SQLite")
			}
			fn(t, newFixtureWith(t, "", storage))
		})
	}
}

func newFixture(t *testing.T, token string) *fixture {
	return newFixtureWith(t, token, config.StorageConfig)
}

func newFixtureWith(t *testing.T, token, storage string) *fixture {
	t.Helper()
	dir := t.TempDir()
	zoneFile := filepath.Join(dir, "file.zone")
	os.WriteFile(zoneFile, []byte("$ORIGIN file.lan.\nwww 60 IN A 192.168.1.20\n"), 0o644)
	path := filepath.Join(dir, "config.yaml")
	src := strings.Replace(baseConfig, "%s", zoneFile, 1)
	dbPath := filepath.Join(dir, "data", "dns-go.db")
	if storage == config.StorageSQLite {
		src += "storage: {type: sqlite, path: " + dbPath + "}\n"
	}
	os.WriteFile(path, []byte(src), 0o644)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := engine.NewService(cfg, engine.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	opened, err := store.Open(cfg, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Store.Close() })
	mgr, err := NewManager(context.Background(), cfg, opened.Store, svc)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(mgr, nil, Options{Token: token})
	return &fixture{t: t, h: h, path: path, dir: dir, svc: svc, storage: storage, dbPath: dbPath}
}

// do sends a request and decodes the JSON response into out (if non-nil).
func (f *fixture) do(method, path string, body any, out any) int {
	f.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if f.h.opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.h.opts.Token)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	if out != nil && w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			f.t.Fatalf("%s %s: decode %q: %v", method, path, w.Body.String(), err)
		}
	}
	return w.Code
}

// saved reads the persisted data through a fresh store instance.
func (f *fixture) saved() config.Data {
	f.t.Helper()
	var st store.Store = store.NewConfigFile(f.path)
	if f.storage == config.StorageSQLite {
		db, _, err := store.OpenSQLite(f.dbPath, config.Data{})
		if err != nil {
			f.t.Fatal(err)
		}
		defer db.Close()
		st = db
	}
	d, err := st.Load(context.Background())
	if err != nil {
		f.t.Fatalf("saved data unreadable: %v", err)
	}
	return d
}

func TestAuth(t *testing.T) {
	f := newFixture(t, "s3cret")
	cases := map[string]int{"": 401, "Bearer wrong": 401, "Bearer s3cret": 200, "s3cret": 401}
	for header, want := range cases {
		req := httptest.NewRequest("GET", "/status", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("Authorization %q: status %d, want %d", header, w.Code, want)
		}
	}
}

func TestStatusAndUnknownEndpoint(t *testing.T) {
	forEachStore(t, func(t *testing.T, f *fixture) {
		var st statusBody
		if code := f.do("GET", "/status", nil, &st); code != 200 || st.Mode != "forwarding" || st.Zones != 2 || st.Cache == nil || st.Filter == nil {
			t.Fatalf("status %d %+v", code, st)
		}
		var e errorBody
		if code := f.do("GET", "/nope", nil, &e); code != 404 || e.Error == "" {
			t.Fatalf("unknown endpoint: %d %+v", code, e)
		}
	})
}

func TestZoneLifecycle(t *testing.T) {
	forEachStore(t, func(t *testing.T, f *fixture) {

		var zones []zoneSummary
		f.do("GET", "/zones", nil, &zones)
		if len(zones) != 2 || !zones[0].Editable || zones[1].Editable || zones[1].Source != "zone_file" {
			t.Fatalf("zones = %+v", zones)
		}

		var z zoneBody
		code := f.do("POST", "/zones", zoneWrite{Origin: "Lab.Example.", Kind: "transparent", Records: []recordBody{
			{Name: "@", Type: "a", Data: "10.0.0.1"},
			{Name: "www", TTL: 60, Type: "CNAME", Data: "@"},
		}}, &z)
		if code != 200 || z.Origin != "lab.example" || z.Kind != "transparent" || len(z.RecordList) != 2 {
			t.Fatalf("create: %d %+v", code, z)
		}
		if r := z.RecordList[1]; r.Name != "www" || r.TTL != 60 || r.Type != "CNAME" || r.Data != "lab.example." {
			t.Fatalf("record = %+v", r)
		}
		if code := f.do("POST", "/zones", zoneWrite{Origin: "lab.example"}, nil); code != 409 {
			t.Fatalf("duplicate zone: %d", code)
		}

		code = f.do("POST", "/zones/lab.example/records", recordBody{Name: "mail", Type: "MX", Data: "10 mx"}, &z)
		if code != 200 || len(z.RecordList) != 3 || z.RecordList[2].Data != "10 mx.lab.example." {
			t.Fatalf("add record: %d %+v", code, z.RecordList)
		}

		// The change is live...
		if r := f.svc.Zones.Lookup("www.lab.example", packet.DNSTypeA, packet.DNSClassIN); len(r.Answers) != 2 {
			t.Fatalf("not live: %+v", r)
		}
		// ...and persisted in canonical zone-file form.
		saved := f.saved()
		if d := saved.Domains[2]; d.Domain != "lab.example" || d.Kind != "transparent" || d.Records[1] != "www 60 IN CNAME lab.example." {
			t.Fatalf("saved = %+v", saved.Domains)
		}

		// Invalid data is rejected without changing anything.
		var e errorBody
		code = f.do("PUT", "/zones/lab.example", zoneWrite{Records: []recordBody{
			{Name: "www", Type: "CNAME", Data: "x.example."},
			{Name: "www", Type: "A", Data: "10.0.0.2"},
		}}, &e)
		if code != 400 || !strings.Contains(e.Error, "CNAME") {
			t.Fatalf("CNAME conflict: %d %+v", code, e)
		}
		for _, bad := range []recordBody{{Type: "BOGUS", Data: "x"}, {Type: "A", Data: "not-an-ip"}, {Type: "A", Data: "1.2.3.4\nevil"}} {
			if code := f.do("POST", "/zones/lab.example/records", bad, nil); code != 400 {
				t.Errorf("record %+v: %d", bad, code)
			}
		}
		f.do("GET", "/zones/lab.example", nil, &z)
		if len(z.RecordList) != 3 {
			t.Fatal("rejected change leaked")
		}

		code = f.do("PUT", "/zones/lab.example", zoneWrite{Kind: "static", Records: []recordBody{{Name: "@", Type: "TXT", Data: `"hello world"`}}}, &z)
		if code != 200 || z.Kind != "static" || len(z.RecordList) != 1 || z.RecordList[0].Data != `"hello world"` {
			t.Fatalf("put: %d %+v", code, z)
		}

		// Single records are addressed by their content-derived ID.
		f.do("POST", "/zones/lab.example/records", recordBody{Name: "tmp", Type: "A", Data: "10.9.9.9"}, &z)
		tmp := z.RecordList[len(z.RecordList)-1]
		if code := f.do("PUT", "/zones/lab.example/records/"+tmp.ID, recordBody{Name: "tmp", Type: "A", Data: "10.9.9.8"}, &z); code != 200 || z.RecordList[1].Data != "10.9.9.8" {
			t.Fatalf("put record: %d %+v", code, z.RecordList)
		}
		if code := f.do("PUT", "/zones/lab.example/records/"+tmp.ID, recordBody{Name: "tmp", Type: "A", Data: "10.9.9.7"}, nil); code != 404 {
			t.Fatalf("stale record id must 404, got %d", code)
		}
		if code := f.do("DELETE", "/zones/lab.example/records/"+z.RecordList[1].ID, nil, &z); code != 200 || len(z.RecordList) != 1 {
			t.Fatalf("delete record: %d %+v", code, z.RecordList)
		}

		if code := f.do("PUT", "/zones/file.lan", zoneWrite{}, nil); code != 409 {
			t.Fatalf("file-backed zones are read-only: %d", code)
		}
		if code := f.do("GET", "/zones/file.lan", nil, &z); code != 200 || len(z.RecordList) != 1 || z.RecordList[0].Name != "www" {
			t.Fatalf("file zone: %d %+v", code, z)
		}
		if code := f.do("DELETE", "/zones/lab.example", nil, nil); code != 204 {
			t.Fatalf("delete: %d", code)
		}
		if code := f.do("GET", "/zones/lab.example", nil, nil); code != 404 {
			t.Fatalf("after delete: %d", code)
		}
		if len(f.saved().Domains) != 2 {
			t.Fatal("delete not persisted")
		}
	})
}

func TestResolve(t *testing.T) {
	forEachStore(t, func(t *testing.T, f *fixture) {
		var res resolveBody
		code := f.do("POST", "/resolve", resolveRequest{Name: "nas.home.lan", Type: "A"}, &res)
		if code != 200 || res.RCode != "NOERROR" || res.Source != "zone" || len(res.Answers) != 1 || res.Answers[0].Data != "192.168.1.10" {
			t.Fatalf("resolve: %d %+v", code, res)
		}
		if res.Answers[0].Name != "nas.home.lan." {
			t.Fatalf("names outside a zone listing are absolute: %q", res.Answers[0].Name)
		}
		f.do("PUT", "/filters/rules", rulesBody{Rules: []string{"||ads.example^"}}, nil)
		f.do("POST", "/resolve", resolveRequest{Name: "x.ads.example"}, &res)
		if res.Source != "filter" || res.Filter == nil || res.Filter.Rule != "||ads.example^" {
			t.Fatalf("blocked resolve: %+v", res)
		}
		if code := f.do("POST", "/resolve", resolveRequest{Name: "a.com", Type: "WAT"}, nil); code != 400 {
			t.Fatalf("bad type: %d", code)
		}
	})
}

func TestFilters(t *testing.T) {
	forEachStore(t, func(t *testing.T, f *fixture) {
		var e struct {
			Error   string      `json:"error"`
			Details []ruleError `json:"details"`
		}
		code := f.do("PUT", "/filters/rules", rulesBody{Rules: []string{"||ok.example^", "||bad domain^", "", "x.com$third-party"}}, &e)
		if code != 400 || len(e.Details) != 2 || e.Details[0].Line != 2 || e.Details[1].Line != 4 {
			t.Fatalf("invalid rules: %d %+v", code, e)
		}
		var rules rulesBody
		if code := f.do("PUT", "/filters/rules", rulesBody{Rules: []string{" ||ok.example^ ", "", "@@||fine.ok.example^"}}, &rules); code != 200 || len(rules.Rules) != 2 {
			t.Fatalf("rules: %d %+v", code, rules)
		}
		var m filterMatch
		f.do("GET", "/filters/check?name=a.ok.example", nil, &m)
		if m.Action != "block" || m.List != config.RulesListName {
			t.Fatalf("check: %+v", m)
		}

		if code := f.do("PUT", "/filters/block_mode", map[string]string{"block_mode": "nxdomain"}, nil); code != 200 || f.svc.Engine.BlockMode() != engine.BlockNXDomain {
			t.Fatalf("block mode: %d", code)
		}
		if code := f.do("PUT", "/filters/block_mode", map[string]string{"block_mode": "explode"}, nil); code != 400 {
			t.Fatalf("bad block mode: %d", code)
		}

		list := filepath.Join(f.dir, "list.txt")
		os.WriteFile(list, []byte("||listed.example^\n"), 0o644)
		var fb filtersBody
		code = f.do("POST", "/filters/lists", listWrite{Name: "mine", File: list}, &fb)
		if code != 200 || len(fb.Lists) != 1 || fb.Lists[0].Status == nil || fb.Lists[0].Status.Rules != 1 {
			t.Fatalf("create list: %d %+v", code, fb)
		}
		if f.svc.Filter.Match("listed.example").Action != filter.Block {
			t.Fatal("list not active")
		}
		if code := f.do("POST", "/filters/lists", listWrite{Name: "mine", File: list}, nil); code != 409 {
			t.Fatalf("duplicate list: %d", code)
		}
		if code := f.do("POST", "/filters/lists", listWrite{Name: "x"}, nil); code != 400 {
			t.Fatalf("list without source: %d", code)
		}
		disabled := false
		f.do("PUT", "/filters/lists/mine", listWrite{File: list, Enabled: &disabled}, &fb)
		if fb.Lists[0].Enabled || f.svc.Filter.Match("listed.example").Action != filter.Pass {
			t.Fatal("disabling a list should unload it")
		}
		if code := f.do("POST", "/filters/lists/missing/refresh", nil, nil); code != 404 {
			t.Fatalf("refresh missing: %d", code)
		}
		if code := f.do("DELETE", "/filters/lists/mine", nil, nil); code != 204 || len(f.saved().Filters.Lists) != 0 {
			t.Fatalf("delete list: %d", code)
		}
		saved := f.saved()
		if saved.Filters.BlockMode != "nxdomain" || len(saved.Filters.Rules) != 2 {
			t.Fatalf("filters not persisted: %+v", saved.Filters)
		}
	})
}

func TestAccess(t *testing.T) {
	forEachStore(t, func(t *testing.T, f *fixture) {
		var a accessBody
		f.do("GET", "/access", nil, &a)
		if a.Allow != nil || a.DenyAction != "refuse" || len(a.Clients) != 0 {
			t.Fatalf("defaults: %+v", a)
		}
		empty := []string{}
		code := f.do("PUT", "/access", accessBody{Allow: &empty, Clients: []clientBody{{Name: "laptop", IDs: []string{"k3y"}, Networks: []string{"192.168.1.20"}}}}, &a)
		if code != 200 || a.Allow == nil || len(*a.Allow) != 0 || a.Clients[0].Name != "laptop" {
			t.Fatalf("put: %d %+v", code, a)
		}
		d := f.svc.Access.Check(accessRequest("192.168.1.20", ""))
		if !d.Allowed || d.Client != "laptop" {
			t.Fatalf("live rules: %+v", d)
		}
		if f.svc.Access.Check(accessRequest("192.168.1.21", "")).Allowed {
			t.Fatal("empty allow should refuse unidentified clients")
		}
		saved := f.saved()
		if saved.Access.Allow == nil || len(*saved.Access.Allow) != 0 {
			t.Fatal("explicit empty allow must survive a save")
		}
		for _, bad := range []accessBody{
			{Clients: []clientBody{{Name: "x", IDs: []string{"bad id"}}}},
			{Allow: &[]string{"300.0.0.0/8"}},
			{DenyAction: "ignore"},
		} {
			if code := f.do("PUT", "/access", bad, nil); code != 400 {
				t.Errorf("%+v: %d", bad, code)
			}
		}
	})
}

func TestStatsAndQueryLog(t *testing.T) {
	s := NewStats()
	now := time.Now()
	s.now = func() time.Time { return now }
	for i := 0; i < logCapacity+10; i++ {
		ev := engine.QueryEvent{Time: now, Name: "a.example", Type: packet.DNSTypeA, Source: engine.SourceUpstream, Client: netip.MustParseAddrPort("192.168.1.2:53")}
		if i%2 == 0 {
			ev.Name, ev.Source = "ads.example", engine.SourceFilter
			ev.Filter = filter.Match{Action: filter.Block, List: "l", Rule: "||ads.example^"}
		}
		if i == logCapacity+9 {
			ev.Name, ev.ClientName = "last.example", "laptop"
		}
		s.Record(ev)
	}
	sum := s.Summary(5, 60)
	if sum.Total != logCapacity+10 || sum.Blocked != (logCapacity+10)/2 || sum.TopBlocked[0].Key != "ads.example" || len(sum.Series) != 24 {
		t.Fatalf("summary = %+v", sum)
	}
	if last := sum.Series[len(sum.Series)-1]; last.Total != logCapacity+10 {
		t.Fatalf("current bucket = %+v", last)
	}
	logs := s.Log(LogQuery{Limit: 3})
	if len(logs) != 3 || logs[0].Name != "last.example" || logs[0].ClientName != "laptop" {
		t.Fatalf("newest first: %+v", logs)
	}
	if got := s.Log(LogQuery{Limit: 10, Source: "filter"}); len(got) != 10 || got[0].FilterRule != "||ads.example^" {
		t.Fatalf("source filter: %+v", got)
	}
	if got := s.Log(LogQuery{Search: "LAPTOP"}); len(got) != 1 {
		t.Fatalf("search: %d", len(got))
	}
	if got := s.Log(LogQuery{Limit: logCapacity}); len(got) != logCapacity {
		t.Fatalf("ring keeps %d entries, got %d", logCapacity, len(got))
	}
}

func accessRequest(addr, id string) (r accessCheck) {
	return accessCheck{Addr: netip.MustParseAddr(addr), ClientID: id}
}

type accessCheck = access.Request

// Other programs add and remove single records through the Manager.
func TestManagerRecords(t *testing.T) {
	forEachStore(t, func(t *testing.T, f *fixture) {
		ctx := context.Background()
		mgr := f.h.mgr
		if origin, ok := mgr.ZoneFor("_acme-challenge.www.home.lan"); !ok || origin != "home.lan" {
			t.Fatalf("ZoneFor = %q %v", origin, ok)
		}
		// Zone files are not editable.
		if _, ok := mgr.ZoneFor("www.file.lan"); ok {
			t.Fatal("zone file offered as editable")
		}
		txt := Record{Name: "_acme-challenge.home.lan.", TTL: 60, Type: "TXT", Data: `"tok-en"`}
		for range 2 { // adding twice keeps one record
			if err := mgr.AddRecord(ctx, txt); err != nil {
				t.Fatal(err)
			}
		}
		got, err := mgr.Lookup("_acme-challenge.home.lan")
		if err != nil || len(got) != 1 || got[0].Type != "TXT" || got[0].Data != `"tok-en"` {
			t.Fatalf("Lookup = %+v %v", got, err)
		}
		var res resolveBody
		f.do("POST", "/resolve", resolveRequest{Name: "_acme-challenge.home.lan", Type: "TXT"}, &res)
		if len(res.Answers) != 1 {
			t.Fatalf("record not served: %+v", res)
		}
		if saved := f.saved(); len(saved.Domains[0].Records) != 2 {
			t.Fatalf("record not stored: %+v", saved.Domains[0].Records)
		}
		// TTL is ignored when removing; removing twice succeeds.
		txt.TTL = 300
		for range 2 {
			if err := mgr.RemoveRecord(ctx, txt); err != nil {
				t.Fatal(err)
			}
		}
		if got, _ := mgr.Lookup("_acme-challenge.home.lan"); len(got) != 0 {
			t.Fatalf("record left: %+v", got)
		}
		if err := mgr.AddRecord(ctx, Record{Name: "x.example.org", TTL: 60, Type: "A", Data: "192.0.2.1"}); !errors.Is(err, ErrNoZone) {
			t.Fatalf("outside every zone: %v", err)
		}
		if err := mgr.RemoveRecord(ctx, Record{Name: "x.example.org", Type: "A", Data: "192.0.2.1"}); err != nil {
			t.Fatalf("removing outside every zone: %v", err)
		}
	})
}

func TestSettingsReadOnlyWithoutReconfigure(t *testing.T) {
	f := newFixture(t, "")
	var s struct {
		Mode     string `json:"mode"`
		Editable bool   `json:"editable"`
	}
	if code := f.do("GET", "/settings", nil, &s); code != 200 || s.Mode != "forwarding" || s.Editable {
		t.Fatalf("settings: %d %+v", code, s)
	}
	if code := f.do("PUT", "/settings", map[string]any{"mode": "forwarding"}, nil); code != 409 {
		t.Fatalf("read-only put: %d", code)
	}
}
