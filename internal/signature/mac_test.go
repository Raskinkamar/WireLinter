package signature

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
)

func TestEvaluateHMACSHA1Recipe(t *testing.T) {
	secret := "vercel-test-secret"
	payload := []byte(`{"type":"deployment.created"}`)
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(payload)
	candidate := hex.EncodeToString(mac.Sum(nil))

	recipe := pack.SignatureRecipe{
		SchemaVersion: 1,
		ID:            "hmac-sha1-test",
		Secret: pack.SignatureSecret{
			Ref:            "webhook-secret",
			Representation: "utf8",
		},
		Bindings: map[string]pack.SignatureBinding{
			"signature-candidates": {
				FromHeader: &pack.SignatureHeaderSource{Name: "X-Signature", Cardinality: "exactly-one"},
			},
			"body": {
				FromRawBody: &pack.SignatureRawBodySource{RequireFidelity: "exact"},
			},
		},
		Message: []pack.SignatureMessageSegment{{Binding: "body"}},
		Candidates: pack.SignatureCandidates{
			Binding:  "signature-candidates",
			Encoding: "hex",
		},
		MAC: pack.SignatureMAC{Algorithm: "hmac-sha1"},
	}

	envelope := baseEnvelope(payload, time.Unix(1_780_000_000, 0))
	envelope.Request.Headers = []model.Header{{Name: "X-Signature", Value: candidate}}
	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" || out.MessageID != "signature-valid" {
		t.Fatalf("unexpected HMAC-SHA1 result: %#v", out)
	}
}

func TestNewMACRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := newMAC("hmac-md5", []byte("secret")); err == nil {
		t.Fatal("expected unsupported MAC algorithm to be rejected")
	}
}
