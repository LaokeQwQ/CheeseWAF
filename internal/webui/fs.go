// Package webui serves the admin console files baked into the CheeseWAF binary.
package webui

import (
	"embed"
	"io/fs"
)

// dist holds the Vite build copied here by scripts/ci/build-web.sh.
// A committed .keep file keeps `go test` compiling when the UI has not been built.
//
//go:embed all:dist
var dist embed.FS

// FS returns the baked admin UI when index.html is present.
func FS() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}
