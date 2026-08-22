package secretmatch

import (
	"testing"

	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
)

type mapSecrets map[string]string

func (m mapSecrets) Lookup(ref string) (string, bool, error) {
	value, ok := m[ref]
	return value, ok, nil
}

func testRecipe() pack.SecretMatchRecipe {
	return pack.SecretMatchRecipe{
		SchemaVersion: 1,
		ID:            "auth-token",
		Secret:        pack.SecretMatchSecret{Ref: "webhook-token", Representation: "utf8"},
		Candidate: pack.SecretMatchCandidate{FromHeader: &pack.SecretMatchHeaderSource{
			Name: "asaas-access-token", Cardinality: "exactly-one",
		}},
		Comparison: "constant-time-exact",
	}
}

func testEnvelope(headers []model.Header, completeness string) model.Envelope {
	return model.Envelope{
		ID: "env_test", Provider: "test", Request: model.HTTPRequest{
			Method: "POST", URL: "http://localhost/", Headers: headers,
			HeadersCompleteness: completeness, QueryFidelity: "exact", BodyFidelity: "exact",
		},
	}
}

func TestSecretMatchPassesExactHeaderValue(t *testing.T) {
	out, err := Evaluate(testRecipe(), testEnvelope([]model.Header{{Name: "Asaas-Access-Token", Value: "secret-value"}}, "complete"), mapSecrets{"webhook-token": "secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" || out.MessageID != "secret-match-valid" {
		t.Fatalf("unexpected outcome: %#v", out)
	}
}

func TestSecretMatchDoesNotTrimCandidate(t *testing.T) {
	out, err := Evaluate(testRecipe(), testEnvelope([]model.Header{{Name: "asaas-access-token", Value: "secret-value "}}, "complete"), mapSecrets{"webhook-token": "secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "secret-mismatch" {
		t.Fatalf("expected exact comparison failure, got %#v", out)
	}
}

func TestSecretMatchMissingHeaderRespectsEvidenceCompleteness(t *testing.T) {
	complete, err := Evaluate(testRecipe(), testEnvelope(nil, "complete"), mapSecrets{"webhook-token": "secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	if complete.Kind != "fail" || complete.MessageID != "missing-secret-input" {
		t.Fatalf("complete capture should prove absence: %#v", complete)
	}

	partial, err := Evaluate(testRecipe(), testEnvelope(nil, "partial"), mapSecrets{"webhook-token": "secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	if partial.Kind != "open" || partial.MessageID != "insufficient-header-evidence" {
		t.Fatalf("partial capture should remain open: %#v", partial)
	}
}

func TestSecretMatchMissingConfiguredSecretIsOpen(t *testing.T) {
	out, err := Evaluate(testRecipe(), testEnvelope([]model.Header{{Name: "asaas-access-token", Value: "secret-value"}}, "complete"), mapSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "open" || out.MessageID != "secret-unavailable" {
		t.Fatalf("unexpected outcome: %#v", out)
	}
}

func TestSecretMatchDuplicateHeaderIsAmbiguous(t *testing.T) {
	out, err := Evaluate(testRecipe(), testEnvelope([]model.Header{
		{Name: "asaas-access-token", Value: "secret-value"},
		{Name: "Asaas-Access-Token", Value: "secret-value"},
	}, "complete"), mapSecrets{"webhook-token": "secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "ambiguous-secret-input" {
		t.Fatalf("unexpected outcome: %#v", out)
	}
}

func TestSecretMatchPassesExactQueryValue(t *testing.T) {
	recipe := testRecipe()
	recipe.Candidate = pack.SecretMatchCandidate{FromQuery: &pack.SecretMatchQuerySource{Name: "verify_token", Cardinality: "exactly-one"}}
	envelope := testEnvelope(nil, "complete")
	envelope.Request.Query = []model.QueryItem{{Name: "verify_token", Value: "query-secret"}}
	envelope.Request.QueryFidelity = "exact"
	out, err := Evaluate(recipe, envelope, mapSecrets{"webhook-token": "query-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" || out.MessageID != "secret-match-valid" {
		t.Fatalf("unexpected query outcome: %#v", out)
	}
}

func TestSecretMatchQueryNeedsExactEvidence(t *testing.T) {
	recipe := testRecipe()
	recipe.Candidate = pack.SecretMatchCandidate{FromQuery: &pack.SecretMatchQuerySource{Name: "verify_token", Cardinality: "exactly-one"}}
	envelope := testEnvelope(nil, "complete")
	envelope.Request.Query = []model.QueryItem{{Name: "verify_token", Value: "query-secret"}}
	envelope.Request.QueryFidelity = "reconstructed"
	out, err := Evaluate(recipe, envelope, mapSecrets{"webhook-token": "query-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "open" || out.MessageID != "insufficient-query-evidence" {
		t.Fatalf("reconstructed query must remain open: %#v", out)
	}
}

func TestSecretMatchPassesDecodedJSONPath(t *testing.T) {
	recipe := testRecipe()
	recipe.Candidate = pack.SecretMatchCandidate{FromDecodedBody: &pack.SecretMatchDecodedBodySource{Path: []string{"meta", "passcode"}}}
	envelope := testEnvelope(nil, "complete")
	envelope.Request.DecodedBody = map[string]any{"meta": map[string]any{"passcode": "json-secret"}}
	out, err := Evaluate(recipe, envelope, mapSecrets{"webhook-token": "json-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" || out.MessageID != "secret-match-valid" {
		t.Fatalf("unexpected decoded-body outcome: %#v", out)
	}
}

func TestSecretMatchDecodedJSONMissingBodyIsOpen(t *testing.T) {
	recipe := testRecipe()
	recipe.Candidate = pack.SecretMatchCandidate{FromDecodedBody: &pack.SecretMatchDecodedBodySource{Path: []string{"passcode"}}}
	envelope := testEnvelope(nil, "complete")
	envelope.Request.DecodedBody = nil
	out, err := Evaluate(recipe, envelope, mapSecrets{"webhook-token": "json-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "open" || out.MessageID != "insufficient-body-evidence" {
		t.Fatalf("missing decoded body must remain open: %#v", out)
	}
}

func TestSecretMatchDecodedJSONRejectsNonStringValue(t *testing.T) {
	recipe := testRecipe()
	recipe.Candidate = pack.SecretMatchCandidate{FromDecodedBody: &pack.SecretMatchDecodedBodySource{Path: []string{"passcode"}}}
	envelope := testEnvelope(nil, "complete")
	envelope.Request.DecodedBody = map[string]any{"passcode": 123}
	out, err := Evaluate(recipe, envelope, mapSecrets{"webhook-token": "json-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "malformed-secret-input" {
		t.Fatalf("non-string JSON secret must fail as malformed: %#v", out)
	}
}
