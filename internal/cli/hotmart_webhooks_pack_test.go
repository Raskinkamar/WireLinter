package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

const hotmartDemoHottok = "hottok_wirelint_demo"

func TestValidateBundledHotmartHottokPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "hotmart-webhooks-hottok"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID Hotmart Webhooks Hottok") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintValidHotmartHottokPasses(t *testing.T) {
	t.Setenv("HOTMART_HOTTOK", hotmartDemoHottok)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "hotmart-webhooks-hottok", hotmartTracePath(t)}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "PASS WL-HOTMART-HOTTOK-001 [secret-match-valid]") {
		t.Fatalf("valid Hottok did not pass, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestHotmartWrongHottokFails(t *testing.T) {
	t.Setenv("HOTMART_HOTTOK", "wrong-hottok")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "hotmart-webhooks-hottok", hotmartTracePath(t)}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "FAIL/ERROR WL-HOTMART-HOTTOK-001 [secret-mismatch]") {
		t.Fatalf("wrong Hottok did not fail, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestHotmartMissingHottokLeavesAuthOpen(t *testing.T) {
	unsetEnv(t, "HOTMART_HOTTOK")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "hotmart-webhooks-hottok", hotmartTracePath(t)}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "OPEN WL-HOTMART-HOTTOK-001 [secret-unavailable]") {
		t.Fatalf("missing Hottok did not leave auth open, code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func hotmartTracePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", "hotmart-webhooks-hottok-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}
