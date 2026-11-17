// Package webui embeds the dashboard assets so the binary stays a single file.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed assets
var embedded embed.FS

// FS returns the asset filesystem rooted at assets/.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}

// Read returns one asset by name.
func Read(name string) ([]byte, error) {
	return fs.ReadFile(FS(), name)
}
