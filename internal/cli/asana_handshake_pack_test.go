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

func TestValidateBundledAsanaWebhookHandshakePack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "asana-webhook-handshake"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID Asana Webhook Handshake") || !strings.Contains(stdout.String(), "protocol 1.2") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintValidAsanaWebhookHandshakePasses(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "asana-webhook-handshake", asanaHandshakeTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{
		"WL-ASANA-HANDSHAKE-METHOD-001",
		"WL-ASANA-HANDSHAKE-SECRET-001",
		"WL-ASANA-HANDSHAKE-ACK-001",
		"WL-ASANA-HANDSHAKE-ECHO-001",
	} {
		if !strings.Contains(stdout.String(), "PASS "+ruleID) {
			t.Fatalf("expected %s to pass:\n%s", ruleID, stdout.String())
		}
	}
}

func TestAsanaWebhookHandshakeRejectsWrongEcho(t *testing.T) {
	trace := readAsanaHandshakeTrace(t)
	trace.Envelopes[0].Response.Headers[0].Value = "different-value"
	path := writeAsanaHandshakeTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "asana-webhook-handshake", path}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-ASANA-HANDSHAKE-ECHO-001") {
		t.Fatalf("wrong echoed value must fail echo rule, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestAsanaWebhookHandshakeRejectsDuplicateRequestHeader(t *testing.T) {
	trace := readAsanaHandshakeTrace(t)
	trace.Envelopes[0].Request.Headers = append(trace.Envelopes[0].Request.Headers, model.Header{Name: "x-hook-secret", Value: "fixture-hook-value"})
	path := writeAsanaHandshakeTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "asana-webhook-handshake", path}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-ASANA-HANDSHAKE-SECRET-001") {
		t.Fatalf("duplicate request header must fail uniqueness rule, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func asanaHandshakeTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "asana-webhook-handshake-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readAsanaHandshakeTrace(t *testing.T) model.Trace {
	t.Helper()
	raw, err := os.ReadFile(asanaHandshakeTracePath(t))
	if err != nil {
		t.Fatal(err)
	}
	var trace model.Trace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatalf("decode Asana handshake trace fixture: %v", err)
	}
	return trace
}

func writeAsanaHandshakeTrace(t *testing.T, trace model.Trace) string {
	t.Helper()
	raw, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "asana-webhook-handshake-trace.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
