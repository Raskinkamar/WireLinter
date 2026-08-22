package spec

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

func TestRegistryValidatesCanonicalTrace(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	trace := model.Trace{
		SchemaVersion: 1,
		TraceID:       "trace_test_1",
		Provider:      "stripe",
		StartedAt:     time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
		Envelopes: []model.Envelope{{
			ID:         "env_1",
			Provider:   "stripe",
			ReceivedAt: time.Date(2026, 8, 17, 12, 0, 1, 0, time.UTC),
			Request: model.HTTPRequest{
				Method:              "POST",
				URL:                 "http://localhost:4242/webhook",
				Headers:             []model.Header{{Name: "Stripe-Signature", Value: "t=1,v1=abc"}},
				HeadersCompleteness: "complete",
				RawQuery:            "",
				QueryFidelity:       "exact",
				BodyFidelity:        "exact",
				RawBodyBase64:       []byte(`{"id":"evt_1"}`),
			},
		}},
		Observations: []model.Observation{},
	}
	if err := registry.Validate("trace-v1.schema.json", trace); err != nil {
		t.Fatalf("valid trace rejected: %v", err)
	}
}

func TestRegistryAllowsUnavailableEvidenceWhenDeclared(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	trace := model.Trace{
		SchemaVersion: 1,
		TraceID:       "trace_no_raw_body",
		Provider:      "stripe",
		StartedAt:     time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
		Envelopes: []model.Envelope{{
			ID:         "env_1",
			Provider:   "stripe",
			ReceivedAt: time.Date(2026, 8, 17, 12, 0, 1, 0, time.UTC),
			Request: model.HTTPRequest{
				Method:              "POST",
				URL:                 "http://localhost:4242/webhook",
				Headers:             []model.Header{},
				HeadersCompleteness: "unavailable",
				RawQuery:            "",
				QueryFidelity:       "unavailable",
				BodyFidelity:        "unavailable",
				RawBodyBase64:       nil,
				DecodedBody:         map[string]any{"id": "evt_1"},
			},
		}},
		Observations: []model.Observation{},
	}
	if err := registry.Validate("trace-v1.schema.json", trace); err != nil {
		t.Fatalf("unavailable evidence trace rejected: %v", err)
	}
}

func TestRegistryRejectsUnavailableHeadersWithCapturedValues(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	invalid := validTraceMap()
	request := invalid["envelopes"].([]any)[0].(map[string]any)["request"].(map[string]any)
	request["headersCompleteness"] = "unavailable"
	request["headers"] = []any{map[string]any{"name": "Stripe-Signature", "value": "x"}}
	if err := registry.Validate("trace-v1.schema.json", invalid); err == nil {
		t.Fatal("expected unavailable headers with captured values to fail validation")
	}
}

func TestRegistryRejectsUnavailableBodyWithRawBytes(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	invalid := validTraceMap()
	request := invalid["envelopes"].([]any)[0].(map[string]any)["request"].(map[string]any)
	request["bodyFidelity"] = "unavailable"
	request["rawBodyBase64"] = "e30="
	if err := registry.Validate("trace-v1.schema.json", invalid); err == nil {
		t.Fatal("expected fidelity/raw-body contradiction to fail validation")
	}
}

func TestRegistryRejectsInvalidBase64AndTimestamp(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	invalid := validTraceMap()
	invalid["startedAt"] = "not-a-timestamp"
	request := invalid["envelopes"].([]any)[0].(map[string]any)["request"].(map[string]any)
	request["rawBodyBase64"] = "%%%not-base64%%%"
	if err := registry.Validate("trace-v1.schema.json", invalid); err == nil {
		t.Fatal("expected invalid base64/timestamp trace to fail validation")
	}
}

func TestRegistryRejectsUnknownSchema(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate("does-not-exist.schema.json", map[string]any{}); err == nil {
		t.Fatal("expected unknown schema error")
	}
}

func TestNormalizeCELUsesNativeNumericTypes(t *testing.T) {
	input := map[string]any{
		"status":   500,
		"duration": 12.5,
		"nested": []any{
			json.Number("42"),
			json.Number("1.25e2"),
		},
	}

	normalized, err := NormalizeCEL(input)
	if err != nil {
		t.Fatal(err)
	}
	root, ok := normalized.(map[string]any)
	if !ok {
		t.Fatalf("NormalizeCEL returned %T", normalized)
	}
	if value, ok := root["status"].(int64); !ok || value != 500 {
		t.Fatalf("status = %#v (%T), want int64(500)", root["status"], root["status"])
	}
	if value, ok := root["duration"].(float64); !ok || value != 12.5 {
		t.Fatalf("duration = %#v (%T), want float64(12.5)", root["duration"], root["duration"])
	}
	nested := root["nested"].([]any)
	if value, ok := nested[0].(int64); !ok || value != 42 {
		t.Fatalf("nested integer = %#v (%T)", nested[0], nested[0])
	}
	if value, ok := nested[1].(float64); !ok || value != 125 {
		t.Fatalf("nested double = %#v (%T)", nested[1], nested[1])
	}
}

func TestNormalizeCELDecodesOnlyTraceRawBodiesToBytes(t *testing.T) {
	input := map[string]any{
		"rawBodyBase64": "bm90LWEtYm9keS1maWVsZA==",
		"envelopes": []any{map[string]any{
			"request": map[string]any{
				"rawBodyBase64": "cmVxdWVzdC1ieXRlcw==",
			},
			"response": map[string]any{
				"rawBodyBase64": "cmVzcG9uc2UtYnl0ZXM=",
			},
		}},
	}

	normalized, err := NormalizeCEL(input)
	if err != nil {
		t.Fatal(err)
	}
	root := normalized.(map[string]any)
	if root["rawBodyBase64"] != "bm90LWEtYm9keS1maWVsZA==" {
		t.Fatalf("unrelated rawBodyBase64 field changed: %#v", root["rawBodyBase64"])
	}
	envelope := root["envelopes"].([]any)[0].(map[string]any)
	request := envelope["request"].(map[string]any)
	response := envelope["response"].(map[string]any)
	if got, ok := request["rawBodyBase64"].([]byte); !ok || string(got) != "request-bytes" {
		t.Fatalf("request raw body = %#v (%T)", request["rawBodyBase64"], request["rawBodyBase64"])
	}
	if got, ok := response["rawBodyBase64"].([]byte); !ok || string(got) != "response-bytes" {
		t.Fatalf("response raw body = %#v (%T)", response["rawBodyBase64"], response["rawBodyBase64"])
	}
}

func TestNormalizeCELRejectsInvalidTraceRawBodyBase64(t *testing.T) {
	_, err := NormalizeCEL(map[string]any{
		"envelopes": []any{map[string]any{
			"request": map[string]any{"rawBodyBase64": "%%%"},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "decode raw body base64 for CEL bytes") {
		t.Fatalf("expected raw-body base64 decoding error, got %v", err)
	}
}

func TestNormalizeCELRejectsIntegerOutsideInt64(t *testing.T) {
	_, err := NormalizeCEL(map[string]any{"id": json.Number("9223372036854775808")})
	if err == nil || !strings.Contains(err.Error(), "outside CEL int64 range") {
		t.Fatalf("expected CEL int64 range error, got %v", err)
	}
}

func TestNormalizeCELRejectsDoubleOutsideFiniteRange(t *testing.T) {
	_, err := NormalizeCEL(map[string]any{"value": json.Number("1e10000")})
	if err == nil || !strings.Contains(err.Error(), "outside CEL double range") {
		t.Fatalf("expected CEL double range error, got %v", err)
	}
}

func TestNormalizeJSONStillPreservesNumberPrecision(t *testing.T) {
	normalized, err := NormalizeJSON(map[string]any{"id": json.Number("9223372036854775808")})
	if err != nil {
		t.Fatal(err)
	}
	root := normalized.(map[string]any)
	value, ok := root["id"].(json.Number)
	if !ok || value.String() != "9223372036854775808" {
		t.Fatalf("NormalizeJSON lost precision: %#v (%T)", root["id"], root["id"])
	}
}

func validTraceMap() map[string]any {
	return map[string]any{
		"schemaVersion": 1,
		"traceId":       "trace_map",
		"provider":      "stripe",
		"startedAt":     "2026-08-17T12:00:00Z",
		"envelopes": []any{map[string]any{
			"id":         "env_1",
			"provider":   "stripe",
			"receivedAt": "2026-08-17T12:00:00Z",
			"request": map[string]any{
				"method":              "POST",
				"url":                 "http://localhost/webhook",
				"headers":             []any{},
				"headersCompleteness": "complete",
				"rawQuery":            "",
				"queryFidelity":       "exact",
				"bodyFidelity":        "exact",
				"rawBodyBase64":       "e30=",
			},
		}},
		"observations": []any{},
	}
}
