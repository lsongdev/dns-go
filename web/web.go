// Package web embeds the management panel: plain ES modules (Preact + htm)
// with no build step. Edit the files in static/ and reload the page.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// FS returns the panel's files rooted at static/.
func FS() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
