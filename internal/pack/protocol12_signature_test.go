package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoaderLoadsProtocol12SignaturePack(t *testing.T) {
	dir := writeSignaturePack(t, true)
	manifestPath := filepath.Join(dir, "pack.yaml")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(raw), `packProtocol: "1.1"`, `packProtocol: "1.2"`, 1)
	if updated == string(raw) {
		t.Fatal("failed to update signature fixture to protocol 1.2")
	}
	if err := os.WriteFile(manifestPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}

	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Manifest.PackProtocol != "1.2" {
		t.Fatalf("unexpected protocol %q", loaded.Manifest.PackProtocol)
	}
	if _, ok := loaded.Signatures["github-hmac"]; !ok {
		t.Fatalf("protocol 1.2 lost signature recipe support: %#v", loaded.Signatures)
	}
}
