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

func TestProvidersListsBundledOfficialPacks(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"providers"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("providers returned %d: %s", code, stderr.String())
	}

	output := stdout.String()
	for _, provider := range []string{
		"asaas-webhooks",
		"clerk-webhooks",
		"github",
		"gitlab-webhooks",
		"linear-webhooks",
		"mercadopago-webhooks",
		"shopify-https",
		"slack-events-api",
		"stripe",
		"yampi-webhooks",
	} {
		if !strings.Contains(output, provider+"\n") {
			t.Fatalf("provider %q missing from bundled provider list: %q", provider, output)
		}
	}
}

func TestDemoShowsGraphQLFailureButExitsSuccessfully(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"demo"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("demo returned %d: %s", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"WireLinter demo · GitHub GraphQL API",
		"PASS WL-GH-GQL-HTTP-001",
		"FAIL/ERROR WL-GH-GQL-ERRORS-001",
		"This failure is intentional",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("demo output missing %q:\n%s", want, output)
		}
	}
}

func TestDemoRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"demo", "extra"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "no arguments") {
		t.Fatalf("unexpected result: code=%d stderr=%q", code, stderr.String())
	}
}

func TestProvidersCanFilterBrazilRegion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"providers", "--region", "BR"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("providers --region BR returned %d: %s", code, stderr.String())
	}
	output := stdout.String()
	for _, provider := range []string{"asaas-webhooks", "melhor-envio-webhooks", "pagbank-orders-webhooks-authenticity-token", "yampi-webhooks"} {
		if !strings.Contains(output, provider+"\n") {
			t.Fatalf("Brazil provider %q missing from regional list: %q", provider, output)
		}
	}
	if strings.Contains(output, "github\n") || strings.Contains(output, "stripe\n") {
		t.Fatalf("global-only providers leaked into BR filter: %q", output)
	}
}

func TestValidateBundledStripePack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "stripe"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID Stripe") || !strings.Contains(stdout.String(), "protocol 1.1") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestValidateExternalStripePackStillWorks(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", stripePackPath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate external pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID Stripe") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintValidStripeTrace(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_wirelint_demo")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "stripe", stripeTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS WL-ST-SIGNATURE-001 [signature-valid]") {
		t.Fatalf("valid signature was not reported as pass:\n%s", stdout.String())
	}
}

func TestLintStripeWithoutSecretIsOpen(t *testing.T) {
	unsetEnv(t, "STRIPE_WEBHOOK_SECRET")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "stripe", stripeTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("open result must not fail CI, got %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "OPEN WL-ST-SIGNATURE-001 [secret-unavailable]") {
		t.Fatalf("missing secret was not reported as open:\n%s", stdout.String())
	}
}

func TestLintStripeWithWrongSecretFails(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_wrong")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "stripe", stripeTracePath(t)}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong secret should produce integration failure exit 1, got %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-ST-SIGNATURE-001 [signature-mismatch]") {
		t.Fatalf("wrong secret did not produce signature mismatch:\n%s", stdout.String())
	}
}

func TestLintJSONOutputIsPublicReportContract(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_wirelint_demo")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "stripe", "--format", "json", stripeTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("json lint returned %d: %s", code, stderr.String())
	}
	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON report: %v\n%s", err, stdout.String())
	}
	if report.Provider != "stripe" || report.Summary.Pass != 1 || report.Summary.Errors != 0 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestLintRejectsUnknownTraceField(t *testing.T) {
	raw, err := os.ReadFile(stripeTracePath(t))
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(raw, []byte("\"schemaVersion\": 1"), []byte("\"schemaVersion\": 1, \"unexpected\": true"), 1)
	if bytes.Equal(raw, bad) {
		t.Fatal("failed to inject unknown field into Stripe trace fixture")
	}
	path := filepath.Join(t.TempDir(), "bad-trace.json")
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "stripe", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unknown trace field must be execution error exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown field") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}

func TestLintRejectsProviderAndPackTogether(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "stripe", "--pack", stripePackPath(t), stripeTracePath(t)}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("mutually exclusive pack selection must exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}

func TestLintRejectsUnknownBundledProvider(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "does-not-exist", stripeTracePath(t)}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unknown bundled provider must exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not bundled") {
		t.Fatalf("unexpected error: %s", stderr.String())
	}
}

func stripePackPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "packs", "stripe"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func stripeTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "stripe-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	old, present := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func TestLintMissingTraceExplainsCaptureFirst(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"mercadopago-webhooks", "trace.json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("missing trace must exit 2, got %d", code)
	}
	for _, want := range []string{
		"trace file not found: trace.json",
		"A trace is a real HTTP capture",
		"wirelint listen mercadopago-webhooks <local-webhook-url>",
		".wirelint/traces/<trace-id>.json",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("missing %q in error:\n%s", want, stderr.String())
		}
	}
}
