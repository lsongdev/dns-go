package filter

import (
	"os"
	"path/filepath"
	"testing"
)

func mustAdd(t *testing.T, f *Filter, rules ...string) {
	t.Helper()
	for _, r := range rules {
		if err := f.AddRule(r); err != nil {
			t.Fatalf("AddRule(%q): %v", r, err)
		}
	}
}

func TestBasicBlockAndAllow(t *testing.T) {
	f := New()
	mustAdd(t, f,
		"||doubleclick.net^",
		"@@||example.com^",
	)

	cases := map[string]Action{
		"doubleclick.net":         Block,
		"ad.doubleclick.net":      Block,
		"google.com":              Pass,
		"example.com":             Pass,
		"sub.example.com":         Pass,
	}
	for name, want := range cases {
		if got := f.Decide(name); got != want {
			t.Errorf("Decide(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestImportantOverridesAllow(t *testing.T) {
	f := New()
	mustAdd(t, f,
		"@@||example.com^",
		"||ads.example.com^$important",
	)

	if got := f.Decide("example.com"); got != Pass {
		t.Errorf("example.com should pass via allow, got %v", got)
	}
	if got := f.Decide("ads.example.com"); got != Block {
		t.Errorf("ads.example.com should block via $important, got %v", got)
	}
	if got := f.Decide("sub.ads.example.com"); got != Block {
		t.Errorf("sub.ads.example.com should block via $important on parent, got %v", got)
	}
}

func TestPlainDomain(t *testing.T) {
	f := New()
	mustAdd(t, f, "ads.bad.com")

	if got := f.Decide("ads.bad.com"); got != Block {
		t.Errorf("plain domain block: got %v", got)
	}
	if got := f.Decide("other.bad.com"); got != Pass {
		t.Errorf("plain domain should be exact-only, got %v for sibling", got)
	}
}

func TestCaseInsensitive(t *testing.T) {
	f := New()
	mustAdd(t, f, "||Tracker.IO^")

	if got := f.Decide("TRACKER.IO"); got != Block {
		t.Errorf("Decide should be case-insensitive, got %v", got)
	}
	if got := f.Decide("a.tracker.io"); got != Block {
		t.Errorf("subdomain case-insensitive match failed: %v", got)
	}
}

func TestCommentsAndHeaders(t *testing.T) {
	f := New()
	mustAdd(t, f,
		"! this is a comment",
		"# alternate comment",
		"[Adblock Plus 2.0]",
		"",
	)
	if got := f.Decide("anything.com"); got != Pass {
		t.Errorf("comment-only filter should never block, got %v", got)
	}
}

func TestUnsupportedSyntaxWarnSkip(t *testing.T) {
	f := New()
	rules := []string{
		"||example.com^$third-party",
		"||example.com^$domain=foo.com",
		"/regex.*/",
		"##.banner-ad",
		"example.com#@#.popup",
	}
	for _, r := range rules {
		if err := f.AddRule(r); err != nil {
			t.Errorf("AddRule(%q) returned error %v, expected warn-skip with nil", r, err)
		}
	}
	if got := f.Decide("example.com"); got != Pass {
		t.Errorf("unsupported rules should be skipped silently, but example.com is %v", got)
	}
}

func TestSuffixMatch(t *testing.T) {
	f := New()
	mustAdd(t, f, "||ads.com^")

	cases := map[string]Action{
		"ads.com":           Block,
		"a.ads.com":         Block,
		"deep.sub.ads.com":  Block,
		"ads.com.evil.com":  Pass, // should NOT match (suffix is on label boundary only)
		"otherads.com":      Pass,
	}
	for name, want := range cases {
		if got := f.Decide(name); got != want {
			t.Errorf("Decide(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestAllowOnRoot(t *testing.T) {
	f := New()
	mustAdd(t, f,
		"||example.com^",
		"@@||sub.example.com^",
	)

	if got := f.Decide("example.com"); got != Block {
		t.Errorf("root should still block: %v", got)
	}
	if got := f.Decide("sub.example.com"); got != Pass {
		t.Errorf("allow exception should win: %v", got)
	}
	if got := f.Decide("deep.sub.example.com"); got != Pass {
		t.Errorf("allow propagates to subs: %v", got)
	}
	if got := f.Decide("other.example.com"); got != Block {
		t.Errorf("non-allowed sibling should block: %v", got)
	}
}

func TestAddListFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	contents := `! header comment
||tracker.com^
@@||allowed.tracker.com^
||ads.com^$important
ads.bad.com
`
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}

	f := New()
	if err := f.AddListFile(path); err != nil {
		t.Fatal(err)
	}

	cases := map[string]Action{
		"tracker.com":         Block,
		"x.tracker.com":       Block,
		"allowed.tracker.com": Pass,
		"ads.com":             Block,
		"ads.bad.com":         Block,
		"google.com":          Pass,
	}
	for name, want := range cases {
		if got := f.Decide(name); got != want {
			t.Errorf("Decide(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTrailingDot(t *testing.T) {
	f := New()
	mustAdd(t, f, "||evil.com^")
	if got := f.Decide("evil.com."); got != Block {
		t.Errorf("trailing dot should be normalized: %v", got)
	}
}

func TestTrailingPipeAnchor(t *testing.T) {
	f := New()
	mustAdd(t, f,
		"||tracker.com^|",
		"@@||allow.tracker.com^|",
	)
	if got := f.Decide("tracker.com"); got != Block {
		t.Errorf("||X^| should block, got %v", got)
	}
	if got := f.Decide("allow.tracker.com"); got != Pass {
		t.Errorf("@@||X^| should allow, got %v", got)
	}
}

func TestWildcardSkipped(t *testing.T) {
	f := New()
	rules := []string{
		"||ad-host-backup-*.aliyuncs.com^",
		"||*.bad.com^",
	}
	for _, r := range rules {
		if err := f.AddRule(r); err != nil {
			t.Errorf("wildcard rule %q should warn-skip with nil err, got %v", r, err)
		}
	}
	if got := f.Decide("ad-host-backup-1.aliyuncs.com"); got != Pass {
		t.Errorf("wildcard rule should not match anything, got %v", got)
	}
}
