package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

const yampiDemoSecret = "wh_wirelint_demo_yampi"

func TestValidateBundledYampiWebhooksPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "yampi-webhooks"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID Yampi Webhooks") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintValidYampiWebhookPasses(t *testing.T) {
	t.Setenv("YAMPI_WEBHOOK_SECRET", yampiDemoSecret)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "yampi-webhooks", yampiTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{"WL-YAMPI-SIGNATURE-001", "WL-YAMPI-METHOD-001", "WL-YAMPI-ACK-STATUS-001", "WL-YAMPI-ACK-DURATION-001"} {
		if !strings.Contains(stdout.String(), "PASS "+ruleID) {
			t.Fatalf("expected %s to pass:\n%s", ruleID, stdout.String())
		}
	}
}

func TestYampiWrongSecretFailsSignature(t *testing.T) {
	t.Setenv("YAMPI_WEBHOOK_SECRET", "wrong-secret")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "yampi-webhooks", yampiTracePath(t)}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-YAMPI-SIGNATURE-001 [signature-mismatch]") {
		t.Fatalf("wrong secret did not fail signature, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestYampiMissingSecretLeavesSignatureOpen(t *testing.T) {
	unsetEnv(t, "YAMPI_WEBHOOK_SECRET")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "yampi-webhooks", yampiTracePath(t)}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "OPEN WL-YAMPI-SIGNATURE-001 [secret-unavailable]") {
		t.Fatalf("missing secret did not leave signature open, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func yampiTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "yampi-webhooks-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}
