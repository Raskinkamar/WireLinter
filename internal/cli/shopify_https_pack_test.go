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

const shopifyHTTPSDemoSecret = "shpss_wirelint_demo"

func TestValidateBundledShopifyHTTPSPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "shopify-https"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID Shopify HTTPS Webhooks") || !strings.Contains(stdout.String(), "protocol 1.2") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintValidShopifyHTTPSVectorPassesAllRules(t *testing.T) {
	t.Setenv("SHOPIFY_CLIENT_SECRET", shopifyHTTPSDemoSecret)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "shopify-https", shopifyHTTPSTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{
		"WL-SH-HTTPS-SIGNATURE-001",
		"WL-SH-HTTPS-METHOD-001",
		"WL-SH-HTTPS-TOPIC-001",
		"WL-SH-HTTPS-WEBHOOK-ID-001",
		"WL-SH-HTTPS-API-VERSION-001",
		"WL-SH-HTTPS-ACK-STATUS-001",
		"WL-SH-HTTPS-ACK-DURATION-001",
	} {
		if !strings.Contains(stdout.String(), "PASS "+ruleID) {
			t.Fatalf("expected %s to pass:\n%s", ruleID, stdout.String())
		}
	}
}

func TestLintShopifyHTTPSWithoutSecretLeavesOnlySignatureOpen(t *testing.T) {
	unsetEnv(t, "SHOPIFY_CLIENT_SECRET")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "shopify-https", shopifyHTTPSTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("open signature must not fail CI, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "OPEN WL-SH-HTTPS-SIGNATURE-001 [secret-unavailable]") {
		t.Fatalf("missing secret was not reported as open:\n%s", stdout.String())
	}
	if strings.Count(stdout.String(), "OPEN ") != 1 {
		t.Fatalf("expected only signature to remain open:\n%s", stdout.String())
	}
}

func TestLintShopifyHTTPSWithWrongSecretFails(t *testing.T) {
	t.Setenv("SHOPIFY_CLIENT_SECRET", "wrong-secret")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "shopify-https", shopifyHTTPSTracePath(t)}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong secret should produce integration failure exit 1, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-SH-HTTPS-SIGNATURE-001 [signature-mismatch]") {
		t.Fatalf("wrong secret did not produce signature mismatch:\n%s", stdout.String())
	}
}

func TestLintShopifyHTTPSWithoutResponseLeavesAckRulesOpen(t *testing.T) {
	t.Setenv("SHOPIFY_CLIENT_SECRET", shopifyHTTPSDemoSecret)
	trace := readShopifyHTTPSTrace(t)
	trace.Envelopes[0].Response = nil
	path := writeShopifyHTTPSTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "shopify-https", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("missing response evidence should remain open, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{"WL-SH-HTTPS-ACK-STATUS-001", "WL-SH-HTTPS-ACK-DURATION-001"} {
		if !strings.Contains(stdout.String(), "OPEN "+ruleID+" [evidence-unavailable]") {
			t.Fatalf("expected %s to be open:\n%s", ruleID, stdout.String())
		}
	}
}

func TestLintShopifyHTTPSFiveSecondResponseFailsTimeoutRule(t *testing.T) {
	t.Setenv("SHOPIFY_CLIENT_SECRET", shopifyHTTPSDemoSecret)
	trace := readShopifyHTTPSTrace(t)
	trace.Envelopes[0].Response.DurationMS = 5_000
	path := writeShopifyHTTPSTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "shopify-https", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("five-second response should fail Shopify timeout rule, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-SH-HTTPS-ACK-DURATION-001") {
		t.Fatalf("timeout rule did not fail:\n%s", stdout.String())
	}
}

func TestLintShopifyHTTPSMissingTopicWithCompleteCaptureFails(t *testing.T) {
	t.Setenv("SHOPIFY_CLIENT_SECRET", shopifyHTTPSDemoSecret)
	trace := readShopifyHTTPSTrace(t)
	trace.Envelopes[0].Request.Headers = withoutHeader(trace.Envelopes[0].Request.Headers, "x-shopify-topic")
	path := writeShopifyHTTPSTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "shopify-https", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("missing topic in complete capture should fail, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-SH-HTTPS-TOPIC-001") {
		t.Fatalf("topic rule did not fail:\n%s", stdout.String())
	}
}

func TestLintShopifyHTTPSMissingTopicWithPartialCaptureIsOpen(t *testing.T) {
	t.Setenv("SHOPIFY_CLIENT_SECRET", shopifyHTTPSDemoSecret)
	trace := readShopifyHTTPSTrace(t)
	trace.Envelopes[0].Request.Headers = withoutHeader(trace.Envelopes[0].Request.Headers, "x-shopify-topic")
	trace.Envelopes[0].Request.HeadersCompleteness = "partial"
	path := writeShopifyHTTPSTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "shopify-https", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("missing topic in partial capture should remain open, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "OPEN WL-SH-HTTPS-TOPIC-001 [evidence-unavailable]") {
		t.Fatalf("topic rule was not open:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "PASS WL-SH-HTTPS-WEBHOOK-ID-001") {
		t.Fatalf("observed webhook id should still pass in a partial capture:\n%s", stdout.String())
	}
}

func shopifyHTTPSTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "shopify-https-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readShopifyHTTPSTrace(t *testing.T) model.Trace {
	t.Helper()
	raw, err := os.ReadFile(shopifyHTTPSTracePath(t))
	if err != nil {
		t.Fatal(err)
	}
	var trace model.Trace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatalf("decode Shopify HTTPS trace fixture: %v", err)
	}
	return trace
}

func writeShopifyHTTPSTrace(t *testing.T, trace model.Trace) string {
	t.Helper()
	raw, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "shopify-https-trace.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
