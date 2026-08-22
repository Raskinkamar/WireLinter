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

const mercadoPagoDemoSecret = "mp_wirelint_demo_secret"

func TestValidateBundledMercadoPagoWebhooksPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "mercadopago-webhooks"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID Mercado Pago Webhooks") || !strings.Contains(stdout.String(), "protocol 1.2") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintValidMercadoPagoVectorPassesAllRules(t *testing.T) {
	t.Setenv("MERCADOPAGO_WEBHOOK_SECRET", mercadoPagoDemoSecret)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "mercadopago-webhooks", mercadoPagoTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{
		"WL-MP-WEBHOOKS-SIGNATURE-001",
		"WL-MP-WEBHOOKS-METHOD-001",
		"WL-MP-WEBHOOKS-ACK-STATUS-001",
		"WL-MP-WEBHOOKS-ACK-DURATION-001",
	} {
		if !strings.Contains(stdout.String(), "PASS "+ruleID) {
			t.Fatalf("expected %s to pass:\n%s", ruleID, stdout.String())
		}
	}
}

func TestMercadoPagoSignaturePreservesDataIDCase(t *testing.T) {
	t.Setenv("MERCADOPAGO_WEBHOOK_SECRET", mercadoPagoDemoSecret)
	trace := readMercadoPagoTrace(t)
	trace.Envelopes[0].Request.Query[0].Value = "abc123"
	trace.Envelopes[0].Request.RawQuery = "data.id=abc123&type=payment"
	trace.Envelopes[0].Request.URL = "http://localhost:4242/webhook?data.id=abc123&type=payment"
	path := writeMercadoPagoTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "mercadopago-webhooks", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("lowercasing signed data.id must invalidate the current Mercado Pago signature, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-MP-WEBHOOKS-SIGNATURE-001 [signature-mismatch]") {
		t.Fatalf("case change did not produce signature mismatch:\n%s", stdout.String())
	}
}

func TestMercadoPagoWithoutSecretLeavesOnlySignatureOpen(t *testing.T) {
	unsetEnv(t, "MERCADOPAGO_WEBHOOK_SECRET")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "mercadopago-webhooks", mercadoPagoTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("missing secret should not fail CI, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "OPEN WL-MP-WEBHOOKS-SIGNATURE-001 [secret-unavailable]") {
		t.Fatalf("missing secret was not open:\n%s", stdout.String())
	}
	if strings.Count(stdout.String(), "OPEN ") != 1 {
		t.Fatalf("expected only signature to remain open:\n%s", stdout.String())
	}
}

func TestMercadoPagoAcknowledgementAccepts201ButRejects202(t *testing.T) {
	t.Setenv("MERCADOPAGO_WEBHOOK_SECRET", mercadoPagoDemoSecret)

	trace := readMercadoPagoTrace(t)
	trace.Envelopes[0].Response.Status = 201
	path := writeMercadoPagoTrace(t, trace)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "mercadopago-webhooks", path}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "PASS WL-MP-WEBHOOKS-ACK-STATUS-001") {
		t.Fatalf("201 should be accepted, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}

	trace.Envelopes[0].Response.Status = 202
	path = writeMercadoPagoTrace(t, trace)
	stdout.Reset()
	stderr.Reset()
	code = Run([]string{"lint", "--provider", "mercadopago-webhooks", path}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-MP-WEBHOOKS-ACK-STATUS-001") {
		t.Fatalf("202 must not be treated as Mercado Pago acknowledgement success, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestMercadoPagoTwentyTwoSecondResponseFailsDeadline(t *testing.T) {
	t.Setenv("MERCADOPAGO_WEBHOOK_SECRET", mercadoPagoDemoSecret)
	trace := readMercadoPagoTrace(t)
	trace.Envelopes[0].Response.DurationMS = 22_000
	path := writeMercadoPagoTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "mercadopago-webhooks", path}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-MP-WEBHOOKS-ACK-DURATION-001") {
		t.Fatalf("22-second response should fail deadline, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func mercadoPagoTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "mercadopago-webhooks-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readMercadoPagoTrace(t *testing.T) model.Trace {
	t.Helper()
	raw, err := os.ReadFile(mercadoPagoTracePath(t))
	if err != nil {
		t.Fatal(err)
	}
	var trace model.Trace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatalf("decode Mercado Pago trace fixture: %v", err)
	}
	return trace
}

func writeMercadoPagoTrace(t *testing.T, trace model.Trace) string {
	t.Helper()
	raw, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mercadopago-webhooks-trace.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
