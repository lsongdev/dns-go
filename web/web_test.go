package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lsongdev/dns-go/client"
	"github.com/lsongdev/dns-go/config"
	"github.com/lsongdev/dns-go/packet"
	"github.com/lsongdev/dns-go/store"
)

// The assets satisfy the panel module contract (version 1).
func TestManifestFollowsContract(t *testing.T) {
	data, err := fs.ReadFile(UI, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Contract int      `json:"contract"`
		ID       string   `json:"id"`
		Title    string   `json:"title"`
		Entry    string   `json:"entry"`
		Styles   []string `json:"styles"`
		Home     string   `json:"home"`
		Nav      []struct {
			Path, Title string
		} `json:"nav"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Contract != 1 || !regexp.MustCompile(`^[a-z][a-z0-9-]*$`).MatchString(m.ID) || m.Title == "" {
		t.Fatalf("manifest = %+v", m)
	}
	for _, name := range append([]string{m.Entry, "index.html"}, m.Styles...) {
		if _, err := fs.Stat(UI, name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	entry, _ := fs.ReadFile(UI, m.Entry)
	if !regexp.MustCompile(`export (function|const) mount\b`).Match(entry) {
		t.Error("entry does not export mount")
	}
	// Every navigation entry and the home page have a route.
	paths := []string{m.Home}
	for _, n := range m.Nav {
		paths = append(paths, n.Path)
	}
	for _, p := range paths {
		if !strings.Contains(string(entry), `path: '`+p+`'`) {
			t.Errorf("no route for %s", p)
		}
	}
}

var importRE = regexp.MustCompile(`(?:from\s*|import\s*\(?\s*)["'](\.{1,2}/[^"']+)["']`)

// Every relative import in every module must resolve to an embedded file;
// otherwise the panel fails at load time with only a console error.
func TestModuleImportsResolve(t *testing.T) {
	err := fs.WalkDir(UI, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs")) {
			return err
		}
		data, err := fs.ReadFile(UI, p)
		if err != nil {
			return err
		}
		for _, m := range importRE.FindAllStringSubmatch(string(data), -1) {
			if _, err := fs.Stat(UI, path.Join(path.Dir(p), m[1])); err != nil {
				t.Errorf("%s imports %s, which does not exist", p, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStatic(t *testing.T) {
	h := Static(UI)
	get := func(path, etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	index := get("/", "")
	if index.Code != 200 || !strings.Contains(index.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("index: %d %v", index.Code, index.Header())
	}
	if w := get("/", index.Header().Get("ETag")); w.Code != http.StatusNotModified {
		t.Fatalf("revalidation: %d", w.Code)
	}
	for _, path := range []string{"/missing.js", "/pages/", "/../web.go"} {
		if w := get(path, ""); w.Code != 404 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	if !store.SQLiteAvailable {
		t.Skip("built without SQLite")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "panel.db")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// freePort returns a loopback address with a port free for UDP.
func freePort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}

func authoritative(addrs ...string) config.Server {
	s := config.Server{Mode: config.ModeAuthoritative}
	for _, a := range addrs {
		s.Listens = append(s.Listens, config.ListenSpec{Type: "udp", Addr: a})
	}
	return s
}

func query(t *testing.T, addr, name string) *packet.DNSPacket {
	t.Helper()
	q := packet.NewPacket()
	q.AddQuestionA(name)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := client.NewUDPClient(addr).Query(ctx, q)
	if err != nil {
		t.Fatalf("query %s at %s: %v", name, addr, err)
	}
	return res
}

func call(t *testing.T, h http.Handler, method, path, body string, out any) int {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	if out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, w.Body)
		}
	}
	return w.Code
}

// Mounted in a panel: settings and data live in the shared database, the
// API changes both at runtime, and DNS keeps answering across a change.
func TestModuleInSharedDatabase(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	first := freePort(t)
	d, err := New(ctx, db, Options{Server: authoritative(first), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	h := d.Handler()
	zone := `{"origin":"example.lan","records":[
		{"name":"@","ttl":3600,"type":"SOA","data":"ns1 hostmaster 1 7200 3600 1209600 300"},
		{"name":"@","ttl":3600,"type":"NS","data":"ns1"},
		{"name":"www","ttl":60,"type":"A","data":"192.0.2.7"}]}`
	if code := call(t, h, "POST", "/zones", zone, nil); code != 200 {
		t.Fatalf("create zone: %d", code)
	}
	if res := query(t, first, "www.example.lan"); len(res.Answers) != 1 {
		t.Fatalf("answers = %v", res.Answers)
	}

	// Move the listener: the old port closes, the new one answers.
	second := freePort(t)
	body, _ := json.Marshal(authoritative(second))
	var got struct {
		config.Server
		Editable bool `json:"editable"`
	}
	if code := call(t, h, "PUT", "/settings", string(body), &got); code != 200 || !got.Editable || got.Listens[0].Addr != second {
		t.Fatalf("put settings: %d %+v", code, got)
	}
	if res := query(t, second, "www.example.lan"); len(res.Answers) != 1 {
		t.Fatalf("answers after rebinding = %v", res.Answers)
	}
	// Invalid settings are refused and change nothing.
	bad := `{"mode":"forwarding","listens":[{"type":"udp","addr":"` + second + `"}]}`
	if code := call(t, h, "PUT", "/settings", bad, nil); code != 400 {
		t.Fatalf("forwarding without upstreams: %d", code)
	}
	var status struct {
		Listens []struct{ Addr, Error string } `json:"listens"`
	}
	call(t, h, "GET", "/status", "", &status)
	if len(status.Listens) != 1 || status.Listens[0].Addr != second || status.Listens[0].Error != "" {
		t.Fatalf("status listens = %+v", status.Listens)
	}
	d.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("Close closed the shared database: %v", err)
	}

	// The next start reads the stored settings, not the defaults.
	d, err = New(ctx, db, Options{Server: authoritative(first), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if s := d.Settings(); s.Listens[0].Addr != second {
		t.Fatalf("stored settings ignored: %+v", s.Listens)
	}
}

// A listener that cannot bind is reported instead of failing the module.
func TestStartReportsBindErrors(t *testing.T) {
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	free := freePort(t)
	d, err := New(context.Background(), openDB(t), Options{Server: authoritative(taken.LocalAddr().String(), free), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Start(); err == nil {
		t.Fatal("bind error not returned")
	}
	st := d.Listeners()
	if len(st) != 2 || st[0].Error == "" || st[1].Error != "" {
		t.Fatalf("listener status = %+v", st)
	}
}

func TestStandaloneRequiresToken(t *testing.T) {
	d, err := New(context.Background(), openDB(t), Options{Server: authoritative(freePort(t)), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	h := d.Standalone("s3cret")
	cases := []struct {
		path, user, pass, bearer string
		want                     int
	}{
		{path: "/api/status", want: 401},
		{path: "/api/status", bearer: "s3cret", want: 200},
		{path: "/api/status", bearer: "wrong", want: 401},
		{path: "/", user: "admin", pass: "s3cret", want: 200},
		{path: "/", user: "admin", pass: "nope", want: 401},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.path, nil)
		if c.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+c.bearer)
		}
		if c.user != "" {
			req.SetBasicAuth(c.user, c.pass)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != c.want {
			body, _ := io.ReadAll(w.Body)
			t.Errorf("%+v: %d %s", c, w.Code, body)
		}
	}
}

// A server turned off binds nothing, and turning it on or off again
// through the API opens or closes its listeners.
func TestTurningTheServerOnAndOff(t *testing.T) {
	addr := freePort(t)
	srv := authoritative(addr)
	srv.Disabled = true
	d, err := New(context.Background(), openDB(t), Options{Server: srv, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	bound := func() bool {
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return true
		}
		conn.Close()
		return false
	}
	var status struct {
		Enabled bool              `json:"enabled"`
		Listens []json.RawMessage `json:"listens"`
	}
	call(t, d.Handler(), "GET", "/status", "", &status)
	if status.Enabled || len(status.Listens) != 0 || bound() {
		t.Fatalf("off: status %+v, bound %v", status, bound())
	}
	on := authoritative(addr)
	body, _ := json.Marshal(on)
	if code := call(t, d.Handler(), "PUT", "/settings", string(body), nil); code != 200 {
		t.Fatalf("turn on: %d", code)
	}
	call(t, d.Handler(), "GET", "/status", "", &status)
	if !status.Enabled || len(status.Listens) != 1 || !bound() {
		t.Fatalf("on: status %+v, bound %v", status, bound())
	}
	on.Disabled = true
	body, _ = json.Marshal(on)
	call(t, d.Handler(), "PUT", "/settings", string(body), nil)
	if bound() {
		t.Fatal("still bound after turning off")
	}
}
