package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
	"github.com/goccy/go-yaml"
)

func TestStripeReferenceRecipeSupportsRotationAndOneSidedFreshness(t *testing.T) {
	recipe := loadRecipe(t, "stripe-v1.yaml")
	secret := "whsec_test_secret"
	payload := []byte(`{"id":"evt_1"}`)
	ts := int64(1_780_000_000)
	valid := hmacHex([]byte(secret), []byte(fmt.Sprintf("%d.", ts)), payload)

	envelope := baseEnvelope(payload, time.Unix(ts+120, 0))
	envelope.Request.Headers = []model.Header{{Name: "Stripe-Signature", Value: fmt.Sprintf("t=%d,v1=not-hex,v1=%s", ts, valid)}}
	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" || out.MessageID != "signature-valid" {
		t.Fatalf("unexpected Stripe result: %#v", out)
	}

	futureEnvelope := envelope
	futureEnvelope.ReceivedAt = time.Unix(ts-600, 0)
	out, err = Evaluate(recipe, futureEnvelope, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" {
		t.Fatalf("Stripe recipe invented a future bound: %#v", out)
	}

	staleEnvelope := envelope
	staleEnvelope.ReceivedAt = time.Unix(ts+301, 0)
	out, err = Evaluate(recipe, staleEnvelope, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "timestamp-stale" {
		t.Fatalf("expected stale Stripe result, got %#v", out)
	}
}

func TestShopifyReferenceRecipe(t *testing.T) {
	recipe := loadRecipe(t, "shopify.yaml")
	secret := "shopify-secret"
	payload := []byte(`{"topic":"orders/create"}`)
	mac := hmacBytes([]byte(secret), payload)
	envelope := baseEnvelope(payload, time.Unix(1_780_000_000, 0))
	envelope.Request.Headers = []model.Header{{Name: "X-Shopify-Hmac-Sha256", Value: base64.StdEncoding.EncodeToString(mac)}}

	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" {
		t.Fatalf("unexpected Shopify result: %#v", out)
	}
}

func TestGitHubReferenceRecipe(t *testing.T) {
	recipe := loadRecipe(t, "github.yaml")
	secret := "github-secret"
	payload := []byte(`{"action":"opened"}`)
	envelope := baseEnvelope(payload, time.Unix(1_780_000_000, 0))
	envelope.Request.Headers = []model.Header{{Name: "X-Hub-Signature-256", Value: "sha256=" + hmacHex([]byte(secret), payload)}}

	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" {
		t.Fatalf("unexpected GitHub result: %#v", out)
	}
}

func TestStandardWebhooksReferenceRecipeRejectsFutureTimestamp(t *testing.T) {
	recipe := loadRecipe(t, "standard-webhooks.yaml")
	key := []byte("standard-webhooks-secret")
	secret := "whsec_" + base64.StdEncoding.EncodeToString(key)
	payload := []byte(`{"type":"example"}`)
	ts := int64(1_780_000_000)
	id := "msg_123"
	message := []byte(fmt.Sprintf("%s.%d.%s", id, ts, payload))
	candidate := base64.StdEncoding.EncodeToString(hmacBytes(key, message))

	envelope := baseEnvelope(payload, time.Unix(ts+30, 0))
	envelope.Request.Headers = []model.Header{
		{Name: "Webhook-Id", Value: id},
		{Name: "Webhook-Timestamp", Value: fmt.Sprintf("%d", ts)},
		{Name: "Webhook-Signature", Value: "v0,ignored v1," + candidate},
	}
	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" {
		t.Fatalf("unexpected Standard Webhooks result: %#v", out)
	}

	future := envelope
	future.ReceivedAt = time.Unix(ts-301, 0)
	out, err = Evaluate(recipe, future, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "timestamp-future" {
		t.Fatalf("expected future timestamp failure, got %#v", out)
	}
}

func TestStandardWebhooksVersionedSecretPrefix(t *testing.T) {
	recipe := loadRecipe(t, "standard-webhooks.yaml")
	recipe.Secret.Prefix = "v1,whsec_"
	key := []byte("supabase-versioned-secret")
	secret := "v1,whsec_" + base64.StdEncoding.EncodeToString(key)
	payload := []byte(`{"type":"send_email"}`)
	ts := int64(1_780_000_000)
	id := "msg_supabase_123"
	message := []byte(fmt.Sprintf("%s.%d.%s", id, ts, payload))
	candidate := base64.StdEncoding.EncodeToString(hmacBytes(key, message))

	envelope := baseEnvelope(payload, time.Unix(ts+30, 0))
	envelope.Request.Headers = []model.Header{
		{Name: "Webhook-Id", Value: id},
		{Name: "Webhook-Timestamp", Value: fmt.Sprintf("%d", ts)},
		{Name: "Webhook-Signature", Value: "v1," + candidate},
	}
	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" || out.MessageID != "signature-valid" {
		t.Fatalf("versioned Standard Webhooks secret prefix failed: %#v", out)
	}
}

func TestMercadoPagoReferenceRecipePreservesMixedCaseDataID(t *testing.T) {
	recipe := loadRecipe(t, "mercadopago.yaml")
	secret := "mp-secret"
	dataID := "ORD01JQ4S4Ky8HWQ6NA5PXB65B3D3"
	requestID := "2066ca19-c6f1-498a-be75-1923005edd06"
	ts := "1742505638683"
	manifest := []byte("id:" + dataID + ";request-id:" + requestID + ";ts:" + ts + ";")
	candidate := hmacHex([]byte(secret), manifest)

	envelope := baseEnvelope(nil, time.Unix(1_780_000_000, 0))
	envelope.Request.BodyFidelity = "unavailable"
	envelope.Request.RawBodyBase64 = nil
	envelope.Request.Query = []model.QueryItem{{Name: "data.id", Value: dataID}}
	envelope.Request.QueryFidelity = "exact"
	envelope.Request.RawQuery = "data.id=" + dataID
	envelope.Request.Headers = []model.Header{
		{Name: "x-request-id", Value: requestID},
		{Name: "x-signature", Value: "ts=" + ts + ",v1=" + candidate},
	}

	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "pass" {
		t.Fatalf("Mercado Pago mixed-case ID was not preserved: %#v", out)
	}
}

func TestEvidenceCompletenessControlsMissingSignatureOutcome(t *testing.T) {
	recipe := loadRecipe(t, "github.yaml")
	envelope := baseEnvelope([]byte(`{}`), time.Unix(1_780_000_000, 0))

	envelope.Request.HeadersCompleteness = "complete"
	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "missing-signature" {
		t.Fatalf("complete evidence should prove absence, got %#v", out)
	}

	envelope.Request.HeadersCompleteness = "partial"
	out, err = Evaluate(recipe, envelope, MapSecrets{"webhook-secret": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "open" || out.MessageID != "insufficient-header-evidence" {
		t.Fatalf("partial evidence should remain open, got %#v", out)
	}
}

func TestReconstructedBodyAndMissingSecretRemainOpen(t *testing.T) {
	recipe := loadRecipe(t, "github.yaml")
	payload := []byte(`{}`)
	envelope := baseEnvelope(payload, time.Unix(1_780_000_000, 0))
	envelope.Request.Headers = []model.Header{{Name: "X-Hub-Signature-256", Value: "sha256=" + hmacHex([]byte("secret"), payload)}}
	envelope.Request.BodyFidelity = "reconstructed"

	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "open" || out.MessageID != "insufficient-body-fidelity" {
		t.Fatalf("reconstructed body should be open, got %#v", out)
	}

	envelope.Request.BodyFidelity = "exact"
	out, err = Evaluate(recipe, envelope, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "open" || out.MessageID != "secret-unavailable" {
		t.Fatalf("missing secret should be open, got %#v", out)
	}
}

func TestDuplicateSingularSignatureHeaderIsAmbiguous(t *testing.T) {
	recipe := loadRecipe(t, "github.yaml")
	envelope := baseEnvelope([]byte(`{}`), time.Unix(1_780_000_000, 0))
	envelope.Request.Headers = []model.Header{
		{Name: "X-Hub-Signature-256", Value: "sha256=00"},
		{Name: "x-hub-signature-256", Value: "sha256=11"},
	}
	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "ambiguous-signature-input" {
		t.Fatalf("duplicate singular header should fail deterministically, got %#v", out)
	}
}

func loadRecipe(t *testing.T, name string) pack.SignatureRecipe {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "pack", "testdata", "signatures", name))
	if err != nil {
		t.Fatal(err)
	}
	var recipe pack.SignatureRecipe
	if err := yaml.Unmarshal(raw, &recipe); err != nil {
		t.Fatal(err)
	}
	return recipe
}

func baseEnvelope(payload []byte, receivedAt time.Time) model.Envelope {
	return model.Envelope{
		ID:         "env_test",
		Provider:   "test-provider",
		ReceivedAt: receivedAt,
		Request: model.HTTPRequest{
			Method:              "POST",
			URL:                 "http://localhost/webhook",
			Headers:             []model.Header{},
			HeadersCompleteness: "complete",
			RawQuery:            "",
			QueryFidelity:       "exact",
			Query:               []model.QueryItem{},
			BodyFidelity:        "exact",
			RawBodyBase64:       payload,
		},
	}
}

func hmacBytes(secret []byte, chunks ...[]byte) []byte {
	mac := hmac.New(sha256.New, secret)
	for _, chunk := range chunks {
		_, _ = mac.Write(chunk)
	}
	return mac.Sum(nil)
}

func hmacHex(secret []byte, chunks ...[]byte) string {
	return hex.EncodeToString(hmacBytes(secret, chunks...))
}
