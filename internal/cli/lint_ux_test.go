package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestLintSupportsPositionalProviderShortcut(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_wirelint_demo")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "stripe", stripeTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("positional provider shortcut returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS WL-ST-SIGNATURE-001") {
		t.Fatalf("unexpected output:\n%s", stdout.String())
	}
}

func TestLintSupportsTopLevelProviderShortcut(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_wirelint_demo")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"stripe", stripeTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("top-level provider shortcut returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS WL-ST-SIGNATURE-001") {
		t.Fatalf("unexpected output:\n%s", stdout.String())
	}
}

func TestLintSupportsProviderNamedFlagShortcut(t *testing.T) {
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_wirelint_demo")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--stripe", stripeTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("named provider shortcut returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS WL-ST-SIGNATURE-001") {
		t.Fatalf("unexpected output:\n%s", stdout.String())
	}
}

func TestLintProviderWithoutTraceGivesActionableError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--mercadopago-webhooks"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("missing trace must exit 2, got %d", code)
	}
	for _, want := range []string{"trace missing for mercadopago-webhooks", "wirelint mercadopago-webhooks <trace.json>"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("missing %q in actionable error: %s", want, stderr.String())
		}
	}
}
