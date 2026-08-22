package packs

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
)

// official contains the exact provider-pack source files that ship in the
// repository. The standalone Go binary imports this package, so official packs
// travel with the executable instead of requiring a separate data directory.
//
// Keep this wildcard provider-agnostic: adding a new top-level pack directory
// with a pack.yaml should not require editing Go source just to bundle it.
//go:embed all:*
var official embed.FS

var providerID = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Provider returns a filesystem rooted at one embedded official provider pack.
// The returned filesystem starts at pack.yaml and can be passed directly to
// pack.Loader.LoadFS.
func Provider(name string) (fs.FS, error) {
	if !providerID.MatchString(name) {
		return nil, fmt.Errorf("invalid provider id %q", name)
	}
	if _, err := fs.Stat(official, name+"/pack.yaml"); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("official provider %q is not bundled", name)
		}
		return nil, fmt.Errorf("inspect official provider %q: %w", name, err)
	}
	sub, err := fs.Sub(official, name)
	if err != nil {
		return nil, fmt.Errorf("open official provider %q: %w", name, err)
	}
	return sub, nil
}

// Providers lists official provider IDs compiled into this build.
func Providers() []string {
	entries, err := fs.ReadDir(official, ".")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !providerID.MatchString(entry.Name()) {
			continue
		}
		if _, err := fs.Stat(official, entry.Name()+"/pack.yaml"); err == nil {
			out = append(out, entry.Name())
		}
	}
	sort.Strings(out)
	return out
}
