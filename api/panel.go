package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// panelHandler serves the single-page panel. Unknown paths fall back to
// index.html so client-side routes survive a reload.
func panelHandler(fsys fs.FS) http.Handler {
	files := http.FileServerFS(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" || name == "." {
			name = "index.html"
		}
		if _, err := fs.Stat(fsys, name); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if name == "index.html" || r.URL.Path == "/" {
			h.Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
