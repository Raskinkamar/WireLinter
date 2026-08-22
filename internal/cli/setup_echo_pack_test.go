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

func TestSetupEchoContractsPassCanonicalFixtures(t *testing.T) {
	for _, tc := range []struct {
		provider string
		fixture  string
		ruleID   string
	}{
		{"dropbox-webhook-verification", "dropbox-webhook-verification-valid.json", "WL-DROPBOX-VERIFY-ECHO-001"},
		{"microsoft-graph-notification-url-validation", "microsoft-graph-notification-url-validation-valid.json", "WL-GRAPH-VALIDATE-ECHO-001"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{"lint", "--provider", tc.provider, setupEchoTracePath(t, tc.fixture)}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
			}
			if !strings.Contains(stdout.String(), "PASS "+tc.ruleID) {
				t.Fatalf("expected echo rule to pass:\n%s", stdout.String())
			}
		})
	}
}

func TestSetupEchoContractsRejectWrongResponseBody(t *testing.T) {
	for _, tc := range []struct {
		provider string
		fixture  string
		ruleID   string
	}{
		{"dropbox-webhook-verification", "dropbox-webhook-verification-valid.json", "WL-DROPBOX-VERIFY-ECHO-001"},
		{"microsoft-graph-notification-url-validation", "microsoft-graph-notification-url-validation-valid.json", "WL-GRAPH-VALIDATE-ECHO-001"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			trace := readSetupEchoTrace(t, tc.fixture)
			trace.Envelopes[0].Response.RawBodyBase64 = []byte("wrong-value")
			path := writeSetupEchoTrace(t, trace)
			var stdout, stderr bytes.Buffer
			code := Run([]string{"lint", "--provider", tc.provider, path}, &stdout, &stderr)
			if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR "+tc.ruleID) {
				t.Fatalf("wrong echo must fail %s, code=%d stderr=%s stdout=%s", tc.ruleID, code, stderr.String(), stdout.String())
			}
		})
	}
}

func setupEchoTracePath(t *testing.T, fixture string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", fixture))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readSetupEchoTrace(t *testing.T, fixture string) model.Trace {
	t.Helper()
	raw, err := os.ReadFile(setupEchoTracePath(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	var trace model.Trace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatal(err)
	}
	return trace
}

func writeSetupEchoTrace(t *testing.T, trace model.Trace) string {
	t.Helper()
	raw, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "setup-echo-trace.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
