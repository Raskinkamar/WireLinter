package pack

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtocol13LoadsSecretMatchRecipe(t *testing.T) {
	dir := writeSecretMatchPack(t, "1.3")
	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Manifest.PackProtocol != "1.3" {
		t.Fatalf("unexpected protocol %q", loaded.Manifest.PackProtocol)
	}
	if _, ok := loaded.SecretMatches["auth-token"]; !ok {
		t.Fatalf("protocol 1.3 lost secret-match recipe: %#v", loaded.SecretMatches)
	}
}

func TestProtocol12RejectsSecretMatchRecipe(t *testing.T) {
	dir := writeSecretMatchPack(t, "1.2")
	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = loader.LoadDir(dir); err == nil {
		t.Fatal("expected protocol 1.2 pack with secretMatches to be rejected")
	}
}

func writeSecretMatchPack(t *testing.T, protocol string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secret-matches"), 0o700); err != nil {
		t.Fatal(err)
	}

	manifest := `packProtocol: "` + protocol + `"
id: test-auth
name: Test Auth
packVersion: 0.1.0
providerDocsRevision: "2026-08-17"
minWireLinterVersion: 0.1.0
capabilities:
  - passive-lint
secrets:
  token:
    env: TEST_WEBHOOK_TOKEN
    required: false
docs:
  auth-docs:
    url: https://example.com/auth
secretMatches:
  auth-token: secret-matches/auth-token.yaml
rules:
  - rules/auth.yaml
`
	recipe := `schemaVersion: 1
id: auth-token
sourceRefs:
  - auth-docs
secret:
  ref: token
  representation: utf8
candidate:
  fromHeader:
    name: x-auth-token
    cardinality: exactly-one
comparison: constant-time-exact
`
	rule := `schemaVersion: 1
id: WL-TEST-AUTH-001
kind: secret-match
scope: envelope
severity: error
stability: preview
title: Token must match
explanation: Token must match.
secretMatchRef: auth-token
docsRef: auth-docs
`
	for path, content := range map[string]string{
		"pack.yaml":                       manifest,
		"secret-matches/auth-token.yaml": recipe,
		"rules/auth.yaml":                rule,
	} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(path)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
