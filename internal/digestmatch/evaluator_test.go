package digestmatch

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
)

type mapSecrets map[string]string

func (m mapSecrets) Lookup(ref string) (string, bool, error) {
	value, ok := m[ref]
	return value, ok, nil
}

func pagBankRecipe() pack.DigestMatchRecipe {
	dash := "-"
	return pack.DigestMatchRecipe{
		SchemaVersion: 1,
		ID:            "authenticity-token",
		Secret:        pack.DigestMatchSecret{Ref: "token", Representation: "utf8"},
		Candidate:     pack.DigestMatchCandidate{FromHeader: pack.DigestMatchHeaderSource{Name: "x-authenticity-token", Cardinality: "exactly-one", TrimSpace: true}, Encoding: "hex"},
		Message: []pack.DigestMatchSegment{
			{Secret: true},
			{Literal: &dash},
			{FromRawBody: &pack.DigestMatchRawBodySource{RequireFidelity: "exact"}},
		},
		Hash:       pack.DigestMatchHash{Algorithm: "sha256"},
		Comparison: "constant-time-exact",
	}
}

func envelope(payload []byte, header string) model.Envelope {
	return model.Envelope{ID: "env_test", Provider: "test", ReceivedAt: time.Unix(1_780_000_000, 0), Request: model.HTTPRequest{Method: "POST", URL: "https://example.test/webhook", Headers: []model.Header{{Name: "X-Authenticity-Token", Value: header}}, HeadersCompleteness: "complete", QueryFidelity: "exact", BodyFidelity: "exact", RawBodyBase64: payload}}
}

func digest(token string, payload []byte) string {
	sum := sha256.Sum256(append([]byte(token+"-"), payload...))
	return hex.EncodeToString(sum[:])
}

func TestDigestMatchPassesPagBankStyleConstruction(t *testing.T) {
	payload := []byte(`{"id":"ORDE_123"}`)
	out, err := Evaluate(pagBankRecipe(), envelope(payload, digest("token-123", payload)), mapSecrets{"token": "token-123"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" || out.MessageID != "digest-match-valid" {
		t.Fatalf("unexpected outcome: %#v", out)
	}
}

func TestDigestMatchRejectsMismatch(t *testing.T) {
	payload := []byte(`{"id":"ORDE_123"}`)
	out, err := Evaluate(pagBankRecipe(), envelope(payload, digest("other-token", payload)), mapSecrets{"token": "token-123"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "digest-mismatch" {
		t.Fatalf("expected mismatch, got %#v", out)
	}
}

func TestDigestMatchRequiresExactBody(t *testing.T) {
	payload := []byte(`{"id":"ORDE_123"}`)
	env := envelope(payload, digest("token-123", payload))
	env.Request.BodyFidelity = "reconstructed"
	out, err := Evaluate(pagBankRecipe(), env, mapSecrets{"token": "token-123"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "open" || out.MessageID != "insufficient-body-fidelity" {
		t.Fatalf("expected open body fidelity, got %#v", out)
	}
}

func TestDigestMatchMissingSecretIsOpen(t *testing.T) {
	payload := []byte(`{}`)
	out, err := Evaluate(pagBankRecipe(), envelope(payload, digest("token-123", payload)), mapSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "open" || out.MessageID != "secret-unavailable" {
		t.Fatalf("expected secret unavailable, got %#v", out)
	}
}

func TestDigestMatchMissingHeaderRespectsCompleteness(t *testing.T) {
	env := envelope([]byte(`{}`), "")
	env.Request.Headers = nil
	env.Request.HeadersCompleteness = "partial"
	out, err := Evaluate(pagBankRecipe(), env, mapSecrets{"token": "token-123"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "open" || out.MessageID != "insufficient-header-evidence" {
		t.Fatalf("expected incomplete evidence, got %#v", out)
	}
}

func TestDigestMatchRejectsMalformedHex(t *testing.T) {
	out, err := Evaluate(pagBankRecipe(), envelope([]byte(`{}`), "not-hex"), mapSecrets{"token": "token-123"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "malformed-digest" {
		t.Fatalf("expected malformed digest, got %#v", out)
	}
}
