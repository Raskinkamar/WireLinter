package signature

import (
	"testing"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

func TestPresentStripeSignatureWithoutV1IsMissingInputNotMissingHeader(t *testing.T) {
	recipe := loadRecipe(t, "stripe-v1.yaml")
	envelope := baseEnvelope([]byte(`{"id":"evt_1"}`), time.Unix(1_780_000_030, 0))
	envelope.Request.Headers = []model.Header{{Name: "Stripe-Signature", Value: "t=1780000000"}}

	out, err := Evaluate(recipe, envelope, MapSecrets{"webhook-secret": "whsec_test"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != "fail" || out.MessageID != "missing-signature-input" {
		t.Fatalf("present signature carrier without v1 must be missing-signature-input, got %#v", out)
	}
}
