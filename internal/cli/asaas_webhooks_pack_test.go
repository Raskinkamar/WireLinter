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

const asaasDemoToken = "asaas_wirelint_demo_X7mQ9vK2pR8sT4uW6yZ3nC5fH1j"

func TestValidateBundledAsaasWebhooksPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "asaas-webhooks"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID Asaas Webhooks") || !strings.Contains(stdout.String(), "protocol 1.3") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintValidAsaasVectorPassesAllRules(t *testing.T) {
	t.Setenv("ASAAS_WEBHOOK_TOKEN", asaasDemoToken)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "asaas-webhooks", asaasTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{
		"WL-AS-WEBHOOKS-AUTH-001",
		"WL-AS-WEBHOOKS-METHOD-001",
		"WL-AS-WEBHOOKS-ACK-STATUS-001",
		"WL-AS-WEBHOOKS-ACK-DURATION-001",
	} {
		if !strings.Contains(stdout.String(), "PASS "+ruleID) {
			t.Fatalf("expected %s to pass:\n%s", ruleID, stdout.String())
		}
	}
}

func TestAsaasMissingConfiguredTokenLeavesOnlyAuthOpen(t *testing.T) {
	unsetEnv(t, "ASAAS_WEBHOOK_TOKEN")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "asaas-webhooks", asaasTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("missing local token should leave auth open, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "OPEN WL-AS-WEBHOOKS-AUTH-001 [secret-unavailable]") {
		t.Fatalf("auth rule was not open:\n%s", stdout.String())
	}
	if strings.Count(stdout.String(), "OPEN ") != 1 {
		t.Fatalf("expected only auth to remain open:\n%s", stdout.String())
	}
}

func TestAsaasWrongTokenFailsAuthentication(t *testing.T) {
	t.Setenv("ASAAS_WEBHOOK_TOKEN", "wrong-token")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "asaas-webhooks", asaasTracePath(t)}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong token should fail, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-AS-WEBHOOKS-AUTH-001 [secret-mismatch]") {
		t.Fatalf("wrong token did not produce secret mismatch:\n%s", stdout.String())
	}
}

func TestAsaasCurrentAckPolicyRejects201(t *testing.T) {
	t.Setenv("ASAAS_WEBHOOK_TOKEN", asaasDemoToken)
	trace := readAsaasTrace(t)
	trace.Envelopes[0].Response.Status = 201
	path := writeAsaasTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "asaas-webhooks", path}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-AS-WEBHOOKS-ACK-STATUS-001") {
		t.Fatalf("201 must fail current Asaas ACK policy, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestAsaasTenSecondResponseFailsDeadline(t *testing.T) {
	t.Setenv("ASAAS_WEBHOOK_TOKEN", asaasDemoToken)
	trace := readAsaasTrace(t)
	trace.Envelopes[0].Response.DurationMS = 10_000
	path := writeAsaasTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "asaas-webhooks", path}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-AS-WEBHOOKS-ACK-DURATION-001") {
		t.Fatalf("10-second response should fail deadline, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestAsaasMissingAuthHeaderWithCompleteCaptureFails(t *testing.T) {
	t.Setenv("ASAAS_WEBHOOK_TOKEN", asaasDemoToken)
	trace := readAsaasTrace(t)
	trace.Envelopes[0].Request.Headers = withoutHeader(trace.Envelopes[0].Request.Headers, "asaas-access-token")
	path := writeAsaasTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "asaas-webhooks", path}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-AS-WEBHOOKS-AUTH-001 [missing-secret-input]") {
		t.Fatalf("missing auth header in complete capture should fail, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func asaasTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "asaas-webhooks-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readAsaasTrace(t *testing.T) model.Trace {
	t.Helper()
	raw, err := os.ReadFile(asaasTracePath(t))
	if err != nil {
		t.Fatal(err)
	}
	var trace model.Trace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatalf("decode Asaas trace fixture: %v", err)
	}
	return trace
}

func writeAsaasTrace(t *testing.T, trace model.Trace) string {
	t.Helper()
	raw, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "asaas-webhooks-trace.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
