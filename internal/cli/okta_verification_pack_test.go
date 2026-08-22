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

func TestOktaEventHookVerificationPassesCanonicalFixture(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "okta-event-hook-verification", oktaVerificationTracePath(t)}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "PASS WL-OKTA-VERIFY-ECHO-001") {
		t.Fatalf("expected Okta verification echo to pass:\n%s", stdout.String())
	}
}

func TestOktaEventHookVerificationRejectsWrongJSONEcho(t *testing.T) {
	raw, err := os.ReadFile(oktaVerificationTracePath(t))
	if err != nil {
		t.Fatal(err)
	}
	var trace model.Trace
	if err := json.Unmarshal(raw, &trace); err != nil {
		t.Fatal(err)
	}
	trace.Envelopes[0].Response.DecodedBody = map[string]any{"verification": "wrong-value"}
	out, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "okta-verification.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "okta-event-hook-verification", path}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-OKTA-VERIFY-ECHO-001") {
		t.Fatalf("wrong Okta echo must fail, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func oktaVerificationTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "okta-event-hook-verification-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}
