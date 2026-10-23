package filter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func withRules(rules ...string) *Filter {
	f := New()
	f.SetList(List{Name: "test", Rules: rules})
	return f
}

func expect(t *testing.T, f *Filter, cases map[string]Action) {
	t.Helper()
	for name, want := range cases {
		if got := f.Match(name).Action; got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestBasicBlockAndAllow(t *testing.T) {
	expect(t, withRules("||doubleclick.net^", "@@||example.com^"), map[string]Action{
		"doubleclick.net":    Block,
		"ad.doubleclick.net": Block,
		"google.com":         Pass,
		"example.com":        Allow,
		"sub.example.com":    Allow,
	})
}

func TestImportantOverridesAllow(t *testing.T) {
	expect(t, withRules("@@||example.com^", "||ads.example.com^$important"), map[string]Action{
		"example.com":         Allow,
		"ads.example.com":     Block,
		"sub.ads.example.com": Block,
	})
}

func TestPlainDomainIsExact(t *testing.T) {
	expect(t, withRules("ads.bad.com"), map[string]Action{
		"ads.bad.com":   Block,
		"other.bad.com": Pass,
		"x.ads.bad.com": Pass,
	})
}

func TestAllowBeatsExactBlock(t *testing.T) {
	expect(t, withRules("ads.example.com", "@@||example.com^"), map[string]Action{
		"ads.example.com": Allow,
	})
}

func TestCaseAndTrailingDot(t *testing.T) {
	expect(t, withRules("||Tracker.IO^"), map[string]Action{
		"TRACKER.IO":   Block,
		"a.tracker.io": Block,
		"tracker.io.":  Block,
	})
}

func TestSuffixMatchIsOnLabelBoundary(t *testing.T) {
	expect(t, withRules("||ads.com^"), map[string]Action{
		"ads.com":          Block,
		"deep.sub.ads.com": Block,
		"ads.com.evil.com": Pass,
		"otherads.com":     Pass,
	})
}

func TestAllowOnSubdomain(t *testing.T) {
	expect(t, withRules("||example.com^", "@@||sub.example.com^"), map[string]Action{
		"example.com":          Block,
		"sub.example.com":      Allow,
		"deep.sub.example.com": Allow,
		"other.example.com":    Block,
	})
}

func TestTrailingPipeAnchor(t *testing.T) {
	expect(t, withRules("||tracker.com^|", "@@||allow.tracker.com^|"), map[string]Action{
		"tracker.com":       Block,
		"allow.tracker.com": Allow,
	})
}

func TestCommentsUnsupportedAndMalformedAreSkipped(t *testing.T) {
	f := New()
	info := f.SetList(List{Name: "l", Rules: []string{
		"! comment", "# comment", "[Adblock Plus 2.0]", "",
		"||example.com^$third-party",
		"/regex.*/",
		"example.com##.banner-ad",
		"||*.bad.com^",
		"||not a domain^",
		"||good.com^",
	}})
	if info.Rules != 1 || info.Skipped != 5 {
		t.Fatalf("ListInfo = %+v, want 1 rule and 5 skipped", info)
	}
	expect(t, f, map[string]Action{"example.com": Pass, "x.bad.com": Pass, "good.com": Block})
}

func TestParseRule(t *testing.T) {
	r, err := ParseRule("@@||Example.com^$important")
	if err != nil || r == nil || r.Domain != "example.com" || !r.Allow || !r.Important || r.Exact {
		t.Fatalf("ParseRule = %+v, %v", r, err)
	}
	if r, err := ParseRule("! comment"); r != nil || err != nil {
		t.Fatal("comments parse to nil, nil")
	}
	var unsupported *ErrUnsupported
	if _, err := ParseRule("||a.com^$third-party"); !errors.As(err, &unsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
	if _, err := ParseRule("||bad domain^"); err == nil || errors.As(err, &unsupported) {
		t.Fatalf("want malformed error, got %v", err)
	}
}

func TestMatchReportsRuleAndList(t *testing.T) {
	f := New()
	f.SetList(List{Name: "ads", Rules: []string{"||ads.com^"}})
	f.SetList(List{Name: "mine", Kind: AllowList, Rules: []string{"ok.ads.com"}})
	if m := f.Match("x.ads.com"); m.Action != Block || m.List != "ads" || m.Rule != "||ads.com^" {
		t.Fatalf("Match = %+v", m)
	}
	// Plain rules in an allow list are exceptions, never blocks.
	if m := f.Match("ok.ads.com"); m.Action != Allow || m.List != "mine" {
		t.Fatalf("Match = %+v", m)
	}
}

func TestListsReplaceAndRemove(t *testing.T) {
	f := New()
	f.SetList(List{Name: "a", Rules: []string{"||one.com^"}})
	f.SetList(List{Name: "b", Rules: []string{"||two.com^"}})
	f.SetList(List{Name: "a", Rules: []string{"||three.com^"}})
	expect(t, f, map[string]Action{"one.com": Pass, "two.com": Block, "three.com": Block})
	if lists := f.Lists(); len(lists) != 2 || lists[0].Name != "a" || lists[0].Rules != 1 {
		t.Fatalf("Lists = %+v", lists)
	}
	if !f.RemoveList("b") || f.RemoveList("b") {
		t.Fatal("RemoveList should report existence")
	}
	expect(t, f, map[string]Action{"two.com": Pass})
}

func TestSetListFrom(t *testing.T) {
	f := New()
	info, err := f.SetListFrom("file", BlockList, strings.NewReader("! header\n||tracker.com^\n@@||allowed.tracker.com^\nads.bad.com\n"))
	if err != nil || info.Rules != 3 {
		t.Fatalf("SetListFrom = %+v, %v", info, err)
	}
	expect(t, f, map[string]Action{"x.tracker.com": Block, "allowed.tracker.com": Allow, "ads.bad.com": Block})
}

func TestSubscriptionsFileAndURL(t *testing.T) {
	var body atomic.Value
	body.Store("||remote.com^\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()

	dir := t.TempDir()
	file := filepath.Join(dir, "local.txt")
	if err := os.WriteFile(file, []byte("||local.com^\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(dir, "cache")

	f := New()
	subs := NewSubscriptions(f, SubscriptionOptions{CacheDir: cacheDir})
	err := subs.Set([]Source{
		{Name: "local", File: file},
		{Name: "remote", URL: srv.URL, Refresh: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Files load synchronously; URLs in the background.
	if f.Match("local.com").Action != Block {
		t.Fatal("file source not loaded by Set")
	}
	waitFor(t, func() bool { return f.Match("remote.com").Action == Block })

	body.Store("||updated.com^\n")
	if err := subs.Refresh(context.Background(), "remote"); err != nil {
		t.Fatal(err)
	}
	expect(t, f, map[string]Action{"remote.com": Pass, "updated.com": Block})
	status := subs.Status()
	if len(status) != 2 || status[1].Name != "remote" || status[1].Rules != 1 || status[1].UpdatedAt.IsZero() {
		t.Fatalf("Status = %+v", status)
	}

	// Removing a source removes its rules.
	if err := subs.Set([]Source{{Name: "remote", URL: srv.URL, Refresh: time.Hour}}); err != nil {
		t.Fatal(err)
	}
	if f.Match("local.com").Action != Pass {
		t.Fatal("removed source still filtering")
	}
	subs.Close()

	// A new instance starts from the disk cache even if the server is gone,
	// and a failed refresh keeps those rules.
	srv.Close()
	f2 := New()
	subs2 := NewSubscriptions(f2, SubscriptionOptions{CacheDir: cacheDir})
	defer subs2.Close()
	if err := subs2.Set([]Source{{Name: "remote", URL: srv.URL, Refresh: time.Hour}}); err != nil {
		t.Fatal(err)
	}
	if f2.Match("updated.com").Action != Block {
		t.Fatal("cached list not loaded at startup")
	}
	waitFor(t, func() bool { return subs2.Status()[0].Error != "" })
	if f2.Match("updated.com").Action != Block {
		t.Fatal("failed refresh must keep the previous rules")
	}
}

func TestSubscriptionsRejectInvalidSources(t *testing.T) {
	subs := NewSubscriptions(New(), SubscriptionOptions{})
	defer subs.Close()
	for _, sources := range [][]Source{
		{{Name: "", URL: "http://x"}},
		{{Name: "a"}},
		{{Name: "a", URL: "http://x", File: "y"}},
		{{Name: "a", URL: "http://x"}, {Name: "a", File: "y"}},
		{{Name: "a", URL: "http://x", Kind: "weird"}},
	} {
		if err := subs.Set(sources); err == nil {
			t.Errorf("Set(%+v) should fail", sources)
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
