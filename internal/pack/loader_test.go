package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validManifest = `packProtocol: "1.0"
id: test-provider
name: Test Provider
packVersion: 0.1.0
providerDocsRevision: "2026-08-17"
capabilities:
  - passive-lint
docs:
  webhook:
    url: https://example.invalid/docs/webhooks
    revision: "2026-08-17"
rules:
  - rules/method.yaml
`

const validRule = `schemaVersion: 1
id: WL-TEST-METHOD-001
kind: cel
scope: envelope
severity: error
stability: preview
title: Webhook must use POST
explanation: The provider delivers webhook events using POST.
docsRef: webhook
assert: envelope.request.method == "POST"
evidencePointers:
  - /request/method
`

func TestLoaderAcceptsMinimalPack(t *testing.T) {
	dir := writePack(t, validManifest, map[string]string{
		"rules/method.yaml": validRule,
	})

	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.LoadDir(dir)
	if err != nil {
		t.Fatalf("valid pack rejected: %v", err)
	}
	if loaded.Manifest.PackProtocol != "1.0" || loaded.Manifest.ID != "test-provider" {
		t.Fatalf("unexpected manifest: %#v", loaded.Manifest)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Rule.ID != "WL-TEST-METHOD-001" {
		t.Fatalf("unexpected rules: %#v", loaded.Rules)
	}
	if loaded.Rules[0].AssertProgram == nil {
		t.Fatal("CEL assert was not compiled at pack load")
	}
}

func TestLoaderRejectsUnknownManifestField(t *testing.T) {
	manifest := validManifest + "surpriseField: true\n"
	dir := writePack(t, manifest, map[string]string{"rules/method.yaml": validRule})
	assertLoadFails(t, dir, "unknown")
}

func TestLoaderRejectsDuplicateYAMLKey(t *testing.T) {
	manifest := strings.Replace(validManifest, "name: Test Provider\n", "name: Test Provider\nname: Duplicate\n", 1)
	dir := writePack(t, manifest, map[string]string{"rules/method.yaml": validRule})
	assertLoadFails(t, dir, "mapping key")
}

func TestLoaderRejectsMultipleYAMLDocuments(t *testing.T) {
	manifest := validManifest + "---\nid: second-document\n"
	dir := writePack(t, manifest, map[string]string{"rules/method.yaml": validRule})
	assertLoadFails(t, dir, "multiple YAML documents")
}

func TestLoaderRejectsTraversalPath(t *testing.T) {
	manifest := strings.Replace(validManifest, "rules/method.yaml", "../outside.yaml", 1)
	dir := writePack(t, manifest, nil)
	assertLoadFails(t, dir, "forbidden segment")
}

func TestLoaderRejectsSymlinkEscapingRoot(t *testing.T) {
	outside := t.TempDir()
	outsideRule := filepath.Join(outside, "outside.yaml")
	if err := os.WriteFile(outsideRule, []byte(validRule), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := writePack(t, validManifest, nil)
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideRule, filepath.Join(dir, "rules", "method.yaml")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	assertLoadFails(t, dir, "rule")
}

func TestLoaderRejectsDuplicateRuleIDs(t *testing.T) {
	manifest := strings.Replace(validManifest, "  - rules/method.yaml\n", "  - rules/method.yaml\n  - rules/duplicate.yaml\n", 1)
	dir := writePack(t, manifest, map[string]string{
		"rules/method.yaml":    validRule,
		"rules/duplicate.yaml": validRule,
	})
	assertLoadFails(t, dir, "duplicate rule id")
}

func TestLoaderRejectsMissingDocsRef(t *testing.T) {
	rule := strings.Replace(validRule, "docsRef: webhook", "docsRef: missing-doc", 1)
	dir := writePack(t, validManifest, map[string]string{"rules/method.yaml": rule})
	assertLoadFails(t, dir, "unknown docsRef")
}

func TestLoaderRejectsNonBooleanCEL(t *testing.T) {
	rule := strings.Replace(validRule, `assert: envelope.request.method == "POST"`, "assert: envelope.request.method", 1)
	dir := writePack(t, validManifest, map[string]string{"rules/method.yaml": rule})
	assertLoadFails(t, dir, "must return bool")
}

func TestLoaderEnforcesCELScopeIsolation(t *testing.T) {
	rule := strings.Replace(validRule, `assert: envelope.request.method == "POST"`, "assert: trace.envelopes.size() > 0", 1)
	dir := writePack(t, validManifest, map[string]string{"rules/method.yaml": rule})
	assertLoadFails(t, dir, "undeclared reference")
}

func TestLoaderRejectsUnknownSchemaRef(t *testing.T) {
	rule := `schemaVersion: 1
id: WL-TEST-SCHEMA-001
kind: json-schema
scope: envelope
severity: error
stability: preview
title: Payload shape
explanation: Payload must match provider structure.
docsRef: webhook
targetPointer: /request/decodedBody
schemaRef: missing
`
	dir := writePack(t, validManifest, map[string]string{"rules/method.yaml": rule})
	assertLoadFails(t, dir, "unknown schemaRef")
}

func TestLoaderRejectsExternalProviderSchemaRef(t *testing.T) {
	manifest := strings.Replace(validManifest, "rules:\n", "schemas:\n  event: schemas/event.json\nrules:\n", 1)
	rule := `schemaVersion: 1
id: WL-TEST-SCHEMA-002
kind: json-schema
scope: envelope
severity: error
stability: preview
title: Payload shape
explanation: Payload must match provider structure.
docsRef: webhook
targetPointer: /request/decodedBody
schemaRef: event
`
	dir := writePack(t, manifest, map[string]string{
		"rules/method.yaml": rule,
		"schemas/event.json": `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$ref": "https://example.invalid/remote-schema.json"
}`,
	})
	assertLoadFails(t, dir, "external resource load")
}

func TestLoaderAcceptsLocalProviderSchema(t *testing.T) {
	manifest := strings.Replace(validManifest, "rules:\n", "schemas:\n  event: schemas/event.json\nrules:\n", 1)
	rule := `schemaVersion: 1
id: WL-TEST-SCHEMA-003
kind: json-schema
scope: envelope
severity: error
stability: preview
title: Payload shape
explanation: Payload must contain an id.
docsRef: webhook
targetPointer: /request/decodedBody
schemaRef: event
`
	dir := writePack(t, manifest, map[string]string{
		"rules/method.yaml": rule,
		"schemas/event.json": `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["id"],
  "properties": {"id": {"type": "string"}},
  "additionalProperties": true
}`,
	})

	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.LoadDir(dir)
	if err != nil {
		t.Fatalf("local provider schema rejected: %v", err)
	}
	if loaded.Schemas["event"] == nil {
		t.Fatal("provider schema was not compiled")
	}
}

func writePack(t *testing.T, manifest string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func assertLoadFails(t *testing.T, dir, contains string) {
	t.Helper()
	loader, err := NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.LoadDir(dir)
	if err == nil {
		t.Fatalf("expected load failure containing %q", contains)
	}
	if contains != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(contains)) {
		t.Fatalf("error %q does not contain %q", err, contains)
	}
}
