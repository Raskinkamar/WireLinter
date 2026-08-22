package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

const (
	metaWhatsAppDemoVerifyToken = "meta_verify_demo"
	metaWhatsAppDemoAppSecret   = "meta_wirelint_demo_secret"
)

func TestMetaWhatsAppOfficialPacksValidate(t *testing.T) {
	for _, provider := range []string{"meta-whatsapp-webhook-verification", "meta-whatsapp-webhooks", "meta-whatsapp-cloud-api"} {
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"validate-pack", "--provider", provider}, &stdout, &stderr); code != 0 {
			t.Fatalf("validate %s returned %d: %s", provider, code, stderr.String())
		}
	}
}

func TestMetaWhatsAppV1FixturesPassAllRules(t *testing.T) {
	t.Setenv("META_WEBHOOK_VERIFY_TOKEN", metaWhatsAppDemoVerifyToken)
	t.Setenv("META_APP_SECRET", metaWhatsAppDemoAppSecret)

	tests := []struct {
		provider       string
		fixture        string
		expectedPasses int
	}{
		{"meta-whatsapp-webhook-verification", "meta-whatsapp-webhook-verification-valid.json", 5},
		{"meta-whatsapp-webhooks", "meta-whatsapp-webhooks-valid.json", 6},
		{"meta-whatsapp-cloud-api", "meta-whatsapp-cloud-api-valid.json", 8},
	}

	for _, test := range tests {
		t.Run(test.provider, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"lint", "--provider", test.provider, metaWhatsAppFixturePath(t, test.fixture)}, &stdout, &stderr); code != 0 {
				t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
			}
			if strings.Contains(stdout.String(), "FAIL/") || strings.Contains(stdout.String(), "OPEN ") {
				t.Fatalf("fixture did not fully pass:\n%s", stdout.String())
			}
			if got := strings.Count(stdout.String(), "PASS "); got != test.expectedPasses {
				t.Fatalf("expected %d passing rules, got %d:\n%s", test.expectedPasses, got, stdout.String())
			}
		})
	}
}

func TestMetaWhatsAppWebhookWrongAppSecretFails(t *testing.T) {
	t.Setenv("META_APP_SECRET", "wrong-demo-secret")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "meta-whatsapp-webhooks", metaWhatsAppFixturePath(t, "meta-whatsapp-webhooks-valid.json")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong app secret should produce integration failure exit 1, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-META-WA-WEBHOOK-SIGNATURE-001 [signature-mismatch]") {
		t.Fatalf("wrong app secret did not produce signature mismatch:\n%s", stdout.String())
	}
}

func TestMetaWhatsAppVerificationWrongTokenFails(t *testing.T) {
	t.Setenv("META_WEBHOOK_VERIFY_TOKEN", "wrong-demo-token")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "meta-whatsapp-webhook-verification", metaWhatsAppFixturePath(t, "meta-whatsapp-webhook-verification-valid.json")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong verify token should produce integration failure exit 1, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-META-WA-VERIFY-TOKEN-001 [secret-mismatch]") {
		t.Fatalf("wrong verify token did not produce secret mismatch:\n%s", stdout.String())
	}
}

func TestMetaWhatsAppCloudAPIHTTP200GraphErrorFails(t *testing.T) {
	trace := readMetaWhatsAppTrace(t, "meta-whatsapp-cloud-api-valid.json")
	if trace.Envelopes[0].Response == nil {
		t.Fatal("cloud API fixture must include a response")
	}

	errorBody := map[string]any{
		"error": map[string]any{
			"message": "Invalid OAuth access token.",
			"type":    "OAuthException",
			"code":    190,
		},
	}
	raw, err := json.Marshal(errorBody)
	if err != nil {
		t.Fatal(err)
	}
	trace.Envelopes[0].Response.Status = 200
	trace.Envelopes[0].Response.RawBodyBase64 = raw
	trace.Envelopes[0].Response.DecodedBody = errorBody

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "meta-whatsapp-cloud-api", writeMetaWhatsAppTrace(t, trace)}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("Graph API error inside HTTP 200 should produce integration failure exit 1, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-META-WA-CLOUD-GRAPH-ERROR-001") {
		t.Fatalf("semantic Graph API error was not rejected:\n%s", stdout.String())
	}
}

func metaWhatsAppFixturePath(t *testing.T, fixture string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", fixture))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readMetaWhatsAppTrace(t *testing.T, fixture string) model.Trace {
	t.Helper()
	raw, err := os.ReadFile(metaWhatsAppFixturePath(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	var trace model.Trace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatalf("decode Meta WhatsApp trace fixture: %v", err)
	}
	return trace
}

func writeMetaWhatsAppTrace(t *testing.T, trace model.Trace) string {
	t.Helper()
	raw, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "meta-whatsapp-trace.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
