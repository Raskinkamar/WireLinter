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

const githubOfficialTestSecret = "It's a Secret to Everybody"

func TestValidateBundledGitHubPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "github"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID GitHub Webhooks") || !strings.Contains(stdout.String(), "protocol 1.2") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintValidGitHubOfficialVectorPassesAllRules(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", githubOfficialTestSecret)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "github", githubTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{
		"WL-GH-SIGNATURE-001",
		"WL-GH-METHOD-001",
		"WL-GH-DELIVERY-001",
		"WL-GH-EVENT-001",
		"WL-GH-ACK-STATUS-001",
		"WL-GH-ACK-DURATION-001",
	} {
		if !strings.Contains(stdout.String(), "PASS "+ruleID) {
			t.Fatalf("expected %s to pass:\n%s", ruleID, stdout.String())
		}
	}
}

func TestLintGitHubWithoutSecretLeavesOnlySignatureOpen(t *testing.T) {
	unsetEnv(t, "GITHUB_WEBHOOK_SECRET")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "github", githubTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("open signature must not fail CI, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "OPEN WL-GH-SIGNATURE-001 [secret-unavailable]") {
		t.Fatalf("missing secret was not reported as open:\n%s", stdout.String())
	}
	if strings.Count(stdout.String(), "OPEN ") != 1 {
		t.Fatalf("expected only signature to remain open:\n%s", stdout.String())
	}
}

func TestLintGitHubWithWrongSecretFails(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", "wrong-secret")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "github", githubTracePath(t)}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong secret should produce integration failure exit 1, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-GH-SIGNATURE-001 [signature-mismatch]") {
		t.Fatalf("wrong secret did not produce signature mismatch:\n%s", stdout.String())
	}
}

func TestLintGitHubWithoutResponseLeavesAckRulesOpen(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", githubOfficialTestSecret)
	trace := readGitHubTrace(t)
	trace.Envelopes[0].Response = nil
	path := writeGitHubTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "github", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("missing response evidence should remain open, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{"WL-GH-ACK-STATUS-001", "WL-GH-ACK-DURATION-001"} {
		if !strings.Contains(stdout.String(), "OPEN "+ruleID+" [evidence-unavailable]") {
			t.Fatalf("expected %s to be open:\n%s", ruleID, stdout.String())
		}
	}
}

func TestLintGitHubSlowResponseFailsTimeoutRule(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", githubOfficialTestSecret)
	trace := readGitHubTrace(t)
	trace.Envelopes[0].Response.DurationMS = 10_000
	path := writeGitHubTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "github", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("10 second response should fail GitHub timeout rule, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-GH-ACK-DURATION-001") {
		t.Fatalf("timeout rule did not fail:\n%s", stdout.String())
	}
}

func TestLintGitHubMissingEventHeaderWithCompleteCaptureFails(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", githubOfficialTestSecret)
	trace := readGitHubTrace(t)
	trace.Envelopes[0].Request.Headers = withoutHeader(trace.Envelopes[0].Request.Headers, "x-github-event")
	path := writeGitHubTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "github", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("missing event header in complete capture should fail, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-GH-EVENT-001") {
		t.Fatalf("event-header rule did not fail:\n%s", stdout.String())
	}
}

func TestLintGitHubMissingEventHeaderWithPartialCaptureIsOpen(t *testing.T) {
	t.Setenv("GITHUB_WEBHOOK_SECRET", githubOfficialTestSecret)
	trace := readGitHubTrace(t)
	trace.Envelopes[0].Request.Headers = withoutHeader(trace.Envelopes[0].Request.Headers, "x-github-event")
	trace.Envelopes[0].Request.HeadersCompleteness = "partial"
	path := writeGitHubTrace(t, trace)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "github", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("missing event header in partial capture should remain open, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "OPEN WL-GH-EVENT-001 [evidence-unavailable]") {
		t.Fatalf("event-header rule was not open:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "PASS WL-GH-DELIVERY-001") {
		t.Fatalf("observed delivery header should still pass in a partial capture:\n%s", stdout.String())
	}
}

func githubTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "github-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readGitHubTrace(t *testing.T) model.Trace {
	t.Helper()
	raw, err := os.ReadFile(githubTracePath(t))
	if err != nil {
		t.Fatal(err)
	}
	var trace model.Trace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatalf("decode GitHub trace fixture: %v", err)
	}
	return trace
}

func writeGitHubTrace(t *testing.T, trace model.Trace) string {
	t.Helper()
	raw, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "github-trace.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func withoutHeader(headers []model.Header, name string) []model.Header {
	out := make([]model.Header, 0, len(headers))
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			continue
		}
		out = append(out, header)
	}
	return out
}
