package pack

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtocol14LoadsDigestMatchRecipe(t *testing.T) {
	dir := writeDigestMatchPack(t, "1.4")
	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.DigestMatches["authenticity-token"]; !ok {
		t.Fatalf("protocol 1.4 lost digest-match recipe: %#v", loaded.DigestMatches)
	}
}

func TestProtocol13RejectsDigestMatchRecipe(t *testing.T) {
	dir := writeDigestMatchPack(t, "1.3")
	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = loader.LoadDir(dir); err == nil {
		t.Fatal("expected protocol 1.3 pack with digestMatches to be rejected")
	}
}

func writeDigestMatchPack(t *testing.T, protocol string) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"rules", "digest-matches"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := `packProtocol: "` + protocol + `"
id: test-digest
name: Test Digest
packVersion: 0.1.0
providerDocsRevision: "2026-08-18"
minWireLinterVersion: 0.1.0
capabilities:
  - passive-lint
secrets:
  token:
    env: TEST_DIGEST_TOKEN
    required: false
docs:
  auth-docs:
    url: https://example.com/auth
digestMatches:
  authenticity-token: digest-matches/authenticity-token.yaml
rules:
  - rules/auth.yaml
`
	recipe := `schemaVersion: 1
id: authenticity-token
sourceRefs:
  - auth-docs
secret:
  ref: token
  representation: utf8
candidate:
  fromHeader:
    name: x-authenticity-token
    cardinality: exactly-one
    trimSpace: true
  encoding: hex
message:
  - secret: true
  - literal: "-"
  - fromRawBody:
      requireFidelity: exact
hash:
  algorithm: sha256
comparison: constant-time-exact
`
	rule := `schemaVersion: 1
id: WL-TEST-DIGEST-001
kind: digest-match
scope: envelope
severity: error
stability: preview
title: Digest must match
explanation: Digest must match.
digestMatchRef: authenticity-token
docsRef: auth-docs
`
	for path, content := range map[string]string{"pack.yaml": manifest, "digest-matches/authenticity-token.yaml": recipe, "rules/auth.yaml": rule} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(path)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
