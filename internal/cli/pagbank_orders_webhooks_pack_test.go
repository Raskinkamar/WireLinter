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

const pagBankDemoToken = "pagbank_wirelint_demo_token"

func TestValidateBundledPagBankOrdersWebhookPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "pagbank-orders-webhooks-authenticity-token"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID PagBank Orders Webhooks Authenticity Token") || !strings.Contains(stdout.String(), "protocol 1.4") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintValidPagBankDigestVectorPasses(t *testing.T) {
	t.Setenv("PAGBANK_ACCOUNT_TOKEN", pagBankDemoToken)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "pagbank-orders-webhooks-authenticity-token", pagBankTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{"WL-PAGBANK-ORDERS-AUTHENTICITY-001", "WL-PAGBANK-ORDERS-METHOD-001", "WL-PAGBANK-ORDERS-CONTENT-TYPE-001"} {
		if !strings.Contains(stdout.String(), "PASS "+ruleID) {
			t.Fatalf("expected %s to pass:\n%s", ruleID, stdout.String())
		}
	}
}

func TestPagBankWrongTokenFailsDigest(t *testing.T) {
	t.Setenv("PAGBANK_ACCOUNT_TOKEN", "wrong-token")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "pagbank-orders-webhooks-authenticity-token", pagBankTracePath(t)}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong token should fail, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-PAGBANK-ORDERS-AUTHENTICITY-001 [digest-mismatch]") {
		t.Fatalf("wrong token did not produce digest mismatch:\n%s", stdout.String())
	}
}

func TestPagBankReconstructedBodyLeavesDigestOpen(t *testing.T) {
	t.Setenv("PAGBANK_ACCOUNT_TOKEN", pagBankDemoToken)
	trace := readPagBankTrace(t)
	trace.Envelopes[0].Request.BodyFidelity = "reconstructed"
	path := writePagBankTrace(t, trace)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "pagbank-orders-webhooks-authenticity-token", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("reconstructed body should leave digest open, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "OPEN WL-PAGBANK-ORDERS-AUTHENTICITY-001 [insufficient-body-fidelity]") {
		t.Fatalf("expected digest rule to remain open:\n%s", stdout.String())
	}
}

func TestPagBankMissingTokenLeavesOnlyDigestOpen(t *testing.T) {
	unsetEnv(t, "PAGBANK_ACCOUNT_TOKEN")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "pagbank-orders-webhooks-authenticity-token", pagBankTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("missing token should leave digest open, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "OPEN WL-PAGBANK-ORDERS-AUTHENTICITY-001 [secret-unavailable]") {
		t.Fatalf("expected digest rule to be open:\n%s", stdout.String())
	}
}

func pagBankTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "pagbank-orders-webhooks-authenticity-token-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readPagBankTrace(t *testing.T) model.Trace {
	t.Helper()
	raw, err := os.ReadFile(pagBankTracePath(t))
	if err != nil {
		t.Fatal(err)
	}
	var trace model.Trace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatalf("decode PagBank trace fixture: %v", err)
	}
	return trace
}

func writePagBankTrace(t *testing.T, trace model.Trace) string {
	t.Helper()
	raw, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pagbank-orders-webhooks-trace.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
