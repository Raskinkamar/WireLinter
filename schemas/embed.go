package schemas

import (
	"embed"
	"fmt"
)

// FS contains the versioned public WireLinter schemas used by the runtime.
//
//go:embed *.schema.json
var FS embed.FS

func Read(name string) ([]byte, error) {
	b, err := FS.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read embedded schema %q: %w", name, err)
	}
	return b, nil
}
