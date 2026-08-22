package engine

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
)

const manifestBase = `packProtocol: "1.0"
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
%s
`

func TestEvaluateCELViolationProducesFailResultWithEvidence(t *testing.T) {
	loaded := loadPack(t, map[string]string{
		"rules/method.yaml": `schemaVersion: 1
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
`,
	}, nil)

	report, err := evaluate(t, traceWithMethod("GET"), loaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Summary.Fail != 1 || report.Summary.Errors != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	result := report.Results[0]
	if result.Kind != "fail" || result.Level != "error" || result.RuleID != "WL-TEST-METHOD-001" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(result.EvidenceRefs) != 1 || result.EvidenceRefs[0].JSONPointer != "/envelopes/0/request/method" {
		t.Fatalf("unexpected evidence: %#v", result.EvidenceRefs)
	}
	if result.SubjectRef.JSONPointer != "/envelopes/0" || result.SubjectRef.EnvelopeID != "env_1" {
		t.Fatalf("unexpected subject: %#v", result.SubjectRef)
	}
}

func TestEvaluatePassingRuleProducesPassResult(t *testing.T) {
	loaded := loadPack(t, map[string]string{
		"rules/method.yaml": `schemaVersion: 1
id: WL-TEST-METHOD-002
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
`,
	}, nil)

	report, err := evaluate(t, traceWithMethod("POST"), loaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].Kind != "pass" || report.Results[0].Level != "none" || report.Summary.Pass != 1 {
		t.Fatalf("unexpected pass report: %#v", report)
	}
}

func TestEvaluateWhenFalseProducesNotApplicable(t *testing.T) {
	loaded := loadPack(t, map[string]string{
		"rules/conditional.yaml": `schemaVersion: 1
id: WL-TEST-WHEN-001
kind: cel
scope: envelope
severity: error
stability: preview
title: Conditional rule
explanation: This rule applies only to PATCH requests.
docsRef: webhook
when: envelope.request.method == "PATCH"
assert: false
evidencePointers:
  - /request/method
`,
	}, nil)

	report, err := evaluate(t, traceWithMethod("POST"), loaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].Kind != "notApplicable" || report.Results[0].Level != "none" || report.Summary.NotApplicable != 1 {
		t.Fatalf("unexpected notApplicable report: %#v", report)
	}
}

func TestEvaluateCELRuntimeErrorIsExecutionError(t *testing.T) {
	loaded := loadPack(t, map[string]string{
		"rules/runtime.yaml": `schemaVersion: 1
id: WL-TEST-RUNTIME-001
kind: cel
scope: envelope
severity: error
stability: preview
title: Runtime failure test
explanation: Runtime errors must never become provider violations.
docsRef: webhook
assert: envelope.request.decodedBody.missing == "value"
evidencePointers:
  - /request/decodedBody
`,
	}, nil)
	trace := traceWithMethod("POST")
	trace.Envelopes[0].Request.DecodedBody = map[string]any{"present": true}
	_, err := evaluate(t, trace, loaded)
	if err == nil || !strings.Contains(err.Error(), "assertion evaluation") {
		t.Fatalf("expected CEL execution error, got %v", err)
	}
}

func TestEvaluateMissingEvidencePointerIsExecutionError(t *testing.T) {
	loaded := loadPack(t, map[string]string{
		"rules/evidence.yaml": `schemaVersion: 1
id: WL-TEST-EVIDENCE-001
kind: cel
scope: envelope
severity: error
stability: preview
title: Evidence must resolve
explanation: A violation without valid evidence is not trustworthy.
docsRef: webhook
assert: false
evidencePointers:
  - /request/notThere
`,
	}, nil)
	_, err := evaluate(t, traceWithMethod("POST"), loaded)
	if err == nil || !strings.Contains(err.Error(), "evidence pointer") {
		t.Fatalf("expected evidence resolution error, got %v", err)
	}
}

func TestEvaluateJSONSchemaViolationUsesTargetAsEvidence(t *testing.T) {
	loaded := loadPack(t, map[string]string{
		"rules/payload.yaml": `schemaVersion: 1
id: WL-TEST-PAYLOAD-001
kind: json-schema
scope: envelope
severity: warning
stability: preview
title: Payload must contain id
explanation: The provider payload requires an id string.
docsRef: webhook
targetPointer: /request/decodedBody
schemaRef: event
`,
	}, map[string]string{
		"event": `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["id"],"properties":{"id":{"type":"string"}},"additionalProperties":true}`,
	})
	trace := traceWithMethod("POST")
	trace.Envelopes[0].Request.DecodedBody = map[string]any{"other": "value"}

	report, err := evaluate(t, trace, loaded)
	if err != nil {
		t.Fatal(err)
	}
	result := report.Results[0]
	if result.Kind != "fail" || result.Level != "warning" || report.Summary.Warnings != 1 {
		t.Fatalf("unexpected schema report: %#v", report)
	}
	if got := result.EvidenceRefs[0].JSONPointer; got != "/envelopes/0/request/decodedBody" {
		t.Fatalf("unexpected target evidence %q", got)
	}
	if result.Metadata == nil || result.Metadata["jsonSchema"] == nil {
		t.Fatalf("JSON Schema diagnostic detail missing: %#v", result.Metadata)
	}
}

func TestEvaluateJSONSchemaMissingTargetIsExecutionError(t *testing.T) {
	loaded := loadPack(t, map[string]string{
		"rules/payload.yaml": `schemaVersion: 1
id: WL-TEST-PAYLOAD-002
kind: json-schema
scope: envelope
severity: error
stability: preview
title: Payload shape
explanation: Missing rule targets indicate an invalid evaluation, not a user violation.
docsRef: webhook
targetPointer: /request/decodedBody
schemaRef: event
`,
	}, map[string]string{"event": `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}`})
	trace := traceWithMethod("POST")
	trace.Envelopes[0].Request.DecodedBody = nil
	_, err := evaluate(t, trace, loaded)
	if err == nil || !strings.Contains(err.Error(), "targetPointer") {
		t.Fatalf("expected missing target execution error, got %v", err)
	}
}

func TestEvaluateTraceScopeInfoMapsToFailNote(t *testing.T) {
	loaded := loadPack(t, map[string]string{
		"rules/trace.yaml": `schemaVersion: 1
id: WL-TEST-TRACE-001
kind: cel
scope: trace
severity: info
stability: preview
title: Trace should contain two deliveries
explanation: The test rule demonstrates multi-envelope trace semantics.
docsRef: webhook
assert: trace.envelopes.size() >= 2
evidencePointers:
  - /envelopes
`,
	}, nil)
	report, err := evaluate(t, traceWithMethod("POST"), loaded)
	if err != nil {
		t.Fatal(err)
	}
	result := report.Results[0]
	if result.Kind != "fail" || result.Level != "note" || report.Summary.Notes != 1 {
		t.Fatalf("unexpected trace report: %#v", report)
	}
	if result.SubjectRef.JSONPointer != "" || result.EvidenceRefs[0].JSONPointer != "/envelopes" {
		t.Fatalf("unexpected trace references: %#v", result)
	}
}

func TestEvaluateProviderMismatchIsExecutionError(t *testing.T) {
	loaded := loadPack(t, map[string]string{
		"rules/method.yaml": `schemaVersion: 1
id: WL-TEST-PROVIDER-001
kind: cel
scope: envelope
severity: error
stability: preview
title: Provider match
explanation: Provider identity must be coherent.
docsRef: webhook
assert: true
evidencePointers:
  - /provider
`,
	}, nil)
	trace := traceWithMethod("POST")
	trace.Provider = "different-provider"
	trace.Envelopes[0].Provider = "different-provider"
	_, err := evaluate(t, trace, loaded)
	if err == nil || !strings.Contains(err.Error(), "does not match pack") {
		t.Fatalf("expected provider mismatch, got %v", err)
	}
}

func evaluate(t *testing.T, trace model.Trace, loaded *pack.Loaded) (model.Report, error) {
	t.Helper()
	evaluator, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return evaluator.Evaluate(trace, loaded)
}

func traceWithMethod(method string) model.Trace {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	return model.Trace{
		SchemaVersion: 1,
		TraceID:       "trace_1",
		Provider:      "test-provider",
		StartedAt:     now,
		Envelopes: []model.Envelope{{
			ID:         "env_1",
			Provider:   "test-provider",
			ReceivedAt: now,
			Request: model.HTTPRequest{
				Method:              method,
				URL:                 "http://localhost:8080/webhook",
				Headers:             []model.Header{},
				HeadersCompleteness: "complete",
				RawQuery:            "",
				QueryFidelity:       "exact",
				BodyFidelity:        "exact",
				RawBodyBase64:       []byte(`{}`),
			},
		}},
		Observations: []model.Observation{},
	}
}

func loadPack(t *testing.T, rules map[string]string, schemas map[string]string) *pack.Loaded {
	t.Helper()
	dir := t.TempDir()

	rulePaths := make([]string, 0, len(rules))
	for rel, content := range rules {
		rulePaths = append(rulePaths, rel)
		writeFile(t, dir, rel, content)
	}
	sort.Strings(rulePaths)

	var schemaBlock strings.Builder
	if len(schemas) > 0 {
		schemaBlock.WriteString("schemas:\n")
		names := make([]string, 0, len(schemas))
		for name := range schemas {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			rel := "schemas/" + name + ".json"
			schemaBlock.WriteString("  " + name + ": " + rel + "\n")
			writeFile(t, dir, rel, schemas[name])
		}
	}

	var ruleList strings.Builder
	for _, rel := range rulePaths {
		ruleList.WriteString("  - " + rel + "\n")
	}
	manifest := strings.Replace(manifestBase, "rules:\n%s", schemaBlock.String()+"rules:\n"+ruleList.String(), 1)
	if err := os.WriteFile(filepath.Join(dir, "pack.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	loader, err := pack.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loader.LoadDir(dir)
	if err != nil {
		t.Fatalf("load test pack: %v\nmanifest:\n%s", err, manifest)
	}
	return loaded
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
