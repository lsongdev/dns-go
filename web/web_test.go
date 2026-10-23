package web

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

var importRE = regexp.MustCompile(`(?:from\s*|import\s*\(?\s*)["'](\.{1,2}/[^"']+)["']`)

// Every relative import in every module must resolve to an embedded file;
// otherwise the panel fails at load time with only a console error.
func TestModuleImportsResolve(t *testing.T) {
	fsys := FS()
	for _, required := range []string{"index.html", "app.js", "style.css", "vendor/preact.js", "vendor/hooks.js", "vendor/htm.js"} {
		if _, err := fs.Stat(fsys, required); err != nil {
			t.Errorf("missing %s", required)
		}
	}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".js") {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		for _, m := range importRE.FindAllStringSubmatch(string(data), -1) {
			target := path.Join(path.Dir(p), m[1])
			if _, err := fs.Stat(fsys, target); err != nil {
				t.Errorf("%s imports %s, which does not exist", p, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
