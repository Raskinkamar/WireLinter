package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
)

func TestProtocol12RequiresFalseProducesOpen(t *testing.T) {
	loaded := loadCELProtocolPack(t, "1.2", `schemaVersion: 1
id: WL-TEST-ACK-001
kind: cel
scope: envelope
severity: error
stability: preview
title: Acknowledgement status
explanation: The endpoint must acknowledge successfully.
docsRef: webhook
requires: has(envelope.response)
assert: envelope.response.status >= 200 && envelope.response.status < 300
evidencePointers:
  - /response/status
messages:
  evidence-unavailable: No application response was captured, so acknowledgement cannot be decided.
`)

	report, err := evaluate(t, traceWithMethod("POST"), loaded)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Open != 1 || len(report.Results) != 1 {
		t.Fatalf("unexpected open report: %#v", report)
	}
	result := report.Results[0]
	if result.Kind != "open" || result.Level != "none" || result.MessageID != "evidence-unavailable" {
		t.Fatalf("unexpected open result: %#v", result)
	}
	if result.Message != "No application response was captured, so acknowledgement cannot be decided." {
		t.Fatalf("message override was not used: %q", result.Message)
	}
	if len(result.EvidenceRefs) != 1 || result.EvidenceRefs[0].JSONPointer != "/envelopes/0" {
		t.Fatalf("open result must cite the subject root: %#v", result.EvidenceRefs)
	}
}

func TestProtocol12WhenRunsBeforeRequires(t *testing.T) {
	loaded := loadCELProtocolPack(t, "1.2", `schemaVersion: 1
id: WL-TEST-ACK-002
kind: cel
scope: envelope
severity: error
stability: preview
title: Conditional acknowledgement
explanation: This intentionally does not apply to POST in the test.
docsRef: webhook
when: envelope.request.method == "PATCH"
requires: envelope.response.status == 200
assert: false
evidencePointers:
  - /request/method
`)

	report, err := evaluate(t, traceWithMethod("POST"), loaded)
	if err != nil {
		t.Fatalf("requires must not run after when=false: %v", err)
	}
	if report.Summary.NotApplicable != 1 || report.Results[0].Kind != "notApplicable" {
		t.Fatalf("unexpected result ordering: %#v", report)
	}
}

func TestProtocol12RequiresTrueThenAssertFails(t *testing.T) {
	loaded := loadCELProtocolPack(t, "1.2", acknowledgementRule("WL-TEST-ACK-003"))
	trace := traceWithMethod("POST")
	trace.Envelopes[0].Response = &model.HTTPResponse{
		Status:              500,
		Protocol:            "HTTP/1.1",
		Headers:             []model.Header{},
		HeadersCompleteness: "complete",
		BodyFidelity:        "exact",
		RawBodyBase64:       []byte(`{}`),
		DurationMS:          10,
	}

	report, err := evaluate(t, trace, loaded)
	if err != nil {
		t.Fatal(err)
	}
	result := report.Results[0]
	if result.Kind != "fail" || result.Level != "error" || report.Summary.Errors != 1 {
		t.Fatalf("unexpected fail result: %#v", report)
	}
	if len(result.EvidenceRefs) != 1 || result.EvidenceRefs[0].JSONPointer != "/envelopes/0/response/status" {
		t.Fatalf("unexpected failure evidence: %#v", result.EvidenceRefs)
	}
}

func TestProtocol12RequiresTrueThenAssertPasses(t *testing.T) {
	loaded := loadCELProtocolPack(t, "1.2", acknowledgementRule("WL-TEST-ACK-004"))
	trace := traceWithMethod("POST")
	trace.Envelopes[0].Response = &model.HTTPResponse{
		Status:              204,
		Protocol:            "HTTP/1.1",
		Headers:             []model.Header{},
		HeadersCompleteness: "complete",
		BodyFidelity:        "exact",
		RawBodyBase64:       []byte{},
		DurationMS:          10,
	}

	report, err := evaluate(t, trace, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Pass != 1 || report.Results[0].Kind != "pass" {
		t.Fatalf("unexpected pass result: %#v", report)
	}
}

func TestProtocol12StringsExtensionSupportsCaseInsensitiveHeaderRule(t *testing.T) {
	loaded := loadCELProtocolPack(t, "1.2", `schemaVersion: 1
id: WL-TEST-HEADER-001
kind: cel
scope: envelope
severity: error
stability: preview
title: Delivery ID header
explanation: A delivery identity header is required.
docsRef: webhook
requires: envelope.request.headersCompleteness == "complete"
assert: envelope.request.headers.exists(h, h.name.lowerAscii() == "x-github-delivery" && h.value != "")
evidencePointers:
  - /request/headers
`)
	trace := traceWithMethod("POST")
	trace.Envelopes[0].Request.Headers = []model.Header{{Name: "X-GitHub-Delivery", Value: "delivery-123"}}

	report, err := evaluate(t, trace, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[0].Kind != "pass" {
		t.Fatalf("case-insensitive header rule did not pass: %#v", report)
	}
}

func TestProtocol12HeaderCompletenessCanProduceOpen(t *testing.T) {
	loaded := loadCELProtocolPack(t, "1.2", `schemaVersion: 1
id: WL-TEST-HEADER-002
kind: cel
scope: envelope
severity: error
stability: preview
title: Delivery ID header
explanation: A delivery identity header is required.
docsRef: webhook
requires: envelope.request.headersCompleteness == "complete"
assert: envelope.request.headers.exists(h, h.name.lowerAscii() == "x-github-delivery" && h.value != "")
evidencePointers:
  - /request/headers
messages:
  evidence-unavailable: Headers were captured partially, so delivery identity presence cannot be decided.
`)
	trace := traceWithMethod("POST")
	trace.Envelopes[0].Request.HeadersCompleteness = "partial"

	report, err := evaluate(t, trace, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[0].Kind != "open" || report.Results[0].MessageID != "evidence-unavailable" {
		t.Fatalf("partial headers should be open: %#v", report)
	}
}

func acknowledgementRule(id string) string {
	return `schemaVersion: 1
id: ` + id + `
kind: cel
scope: envelope
severity: error
stability: preview
title: Acknowledgement status
explanation: A successful acknowledgement must be 2xx.
docsRef: webhook
requires: has(envelope.response)
assert: envelope.response.status >= 200 && envelope.response.status < 300
evidencePointers:
  - /response/status
`
}

func loadCELProtocolPack(t *testing.T, protocol, rule string) *pack.Loaded {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "rules/rule.yaml", rule)
	manifest := `packProtocol: "` + protocol + `"
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
  - rules/rule.yaml
`
	if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := pack.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.LoadDir(dir)
	if err != nil {
		t.Fatalf("load protocol %s test pack: %v\nrule:\n%s", protocol, err, rule)
	}
	return loaded
}

func TestProtocol11RejectsRequires(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "rules/rule.yaml", acknowledgementRule("WL-TEST-COMPAT-001"))
	manifest := `packProtocol: "1.1"
id: test-provider
name: Test Provider
packVersion: 0.1.0
providerDocsRevision: "2026-08-17"
capabilities:
  - passive-lint
docs:
  webhook:
    url: https://example.invalid/docs/webhooks
rules:
  - rules/rule.yaml
`
	if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := pack.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "needs pack protocol 1.2") {
		t.Fatalf("expected 1.1 requires rejection, got %v", err)
	}
}

func TestProtocol11DoesNotSilentlyEnableStringsExtension(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "rules/rule.yaml", `schemaVersion: 1
id: WL-TEST-COMPAT-002
kind: cel
scope: envelope
severity: error
stability: preview
title: Legacy environment
explanation: Protocol 1.1 must not silently gain 1.2 CEL extensions.
docsRef: webhook
assert: "ABC".lowerAscii() == "abc"
evidencePointers:
  - /request
`)
	manifest := `packProtocol: "1.1"
id: test-provider
name: Test Provider
packVersion: 0.1.0
providerDocsRevision: "2026-08-17"
capabilities:
  - passive-lint
docs:
  webhook:
    url: https://example.invalid/docs/webhooks
rules:
  - rules/rule.yaml
`
	if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	loader, err := pack.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	_, err = loader.LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "lowerAscii") {
		t.Fatalf("expected protocol 1.1 lowerAscii compile rejection, got %v", err)
	}
}
