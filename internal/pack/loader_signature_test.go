package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoaderLoadsProtocol11SignaturePack(t *testing.T) {
	dir := writeSignaturePack(t, true)
	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Manifest.PackProtocol != "1.1" {
		t.Fatalf("unexpected protocol %q", loaded.Manifest.PackProtocol)
	}
	if _, ok := loaded.Signatures["github-hmac"]; !ok {
		t.Fatalf("signature recipe not loaded: %#v", loaded.Signatures)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Rule.SignatureRef != "github-hmac" {
		t.Fatalf("signature rule not loaded: %#v", loaded.Rules)
	}
}

func TestLoaderRejectsProtocol10SignaturePack(t *testing.T) {
	dir := writeSignaturePack(t, false)
	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.LoadDir(dir)
	if err == nil {
		t.Fatal("expected protocol 1.0 signature pack rejection")
	}
}

func TestLoaderRejectsUnknownSignatureSecret(t *testing.T) {
	dir := writeSignaturePack(t, true)
	signaturePath := filepath.Join(dir, "signatures", "github-hmac.yaml")
	raw, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(raw), "ref: webhook-secret", "ref: missing-secret", 1)
	if err := os.WriteFile(signaturePath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "unknown secret") {
		t.Fatalf("expected unknown secret rejection, got %v", err)
	}
}

func writeSignaturePack(t *testing.T, protocol11 bool) string {
	t.Helper()
	dir := t.TempDir()
	protocol := "1.1"
	if !protocol11 {
		protocol = "1.0"
	}
	manifest := `packProtocol: "` + protocol + `"
id: test-provider
name: Test Provider
packVersion: 0.1.0
providerDocsRevision: "2026-08-17"
capabilities:
  - passive-lint
secrets:
  webhook-secret:
    env: WEBHOOK_SECRET
docs:
  webhook-signature-docs:
    url: https://example.invalid/webhooks
    revision: "2026-08-17"
signatures:
  github-hmac: signatures/github-hmac.yaml
rules:
  - rules/signature.yaml
`
	writePackFile(t, dir, "pack.yaml", manifest)
	writePackFile(t, dir, "signatures/github-hmac.yaml", `schemaVersion: 1
id: github-hmac
sourceRefs:
  - webhook-signature-docs
secret:
  ref: webhook-secret
  representation: utf8
bindings:
  signature-candidates:
    fromHeader:
      name: X-Hub-Signature-256
      cardinality: exactly-one
  body:
    fromRawBody:
      requireFidelity: exact
message:
  - binding: body
candidates:
  binding: signature-candidates
  encoding: hex
  stripPrefix: "sha256="
mac:
  algorithm: hmac-sha256
`)
	writePackFile(t, dir, "rules/signature.yaml", `schemaVersion: 1
id: WL-TEST-SIGNATURE-001
kind: signature
scope: envelope
severity: error
stability: preview
title: Signature must be valid
explanation: The webhook signature must match.
signatureRef: github-hmac
docsRef: webhook-signature-docs
`)
	return dir
}

func writePackFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
