package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateBundledGitHubGraphQLAPIPack(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"validate-pack", "--provider", "github-graphql-api"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate-pack returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "VALID GitHub GraphQL API") || !strings.Contains(stdout.String(), "protocol 1.2") {
		t.Fatalf("unexpected output: %s", stdout.String())
	}
}

func TestLintGitHubGraphQLValidExchangePasses(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "github-graphql-api", githubGraphQLTracePath(t, "github-graphql-api-valid.json")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("lint returned %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	for _, ruleID := range []string{
		"WL-GH-GQL-DIRECTION-001",
		"WL-GH-GQL-ENDPOINT-001",
		"WL-GH-GQL-METHOD-001",
		"WL-GH-GQL-AUTH-001",
		"WL-GH-GQL-CONTENT-TYPE-001",
		"WL-GH-GQL-REQUEST-001",
		"WL-GH-GQL-HTTP-001",
		"WL-GH-GQL-RESPONSE-001",
		"WL-GH-GQL-ERRORS-001",
		"WL-GH-GQL-RATE-LIMIT-001",
	} {
		if !strings.Contains(stdout.String(), "PASS "+ruleID) {
			t.Fatalf("expected %s to pass:\n%s", ruleID, stdout.String())
		}
	}
}

func TestLintGitHubGraphQLHTTP200WithErrorsFailsSemanticRule(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"lint", "--provider", "github-graphql-api", githubGraphQLTracePath(t, "github-graphql-api-errors.json")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("GraphQL errors should produce integration failure exit 1, got %d: %s\n%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "PASS WL-GH-GQL-HTTP-001") {
		t.Fatalf("HTTP transport rule should pass for HTTP 200:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL/ERROR WL-GH-GQL-ERRORS-001") {
		t.Fatalf("GraphQL errors rule did not fail:\n%s", stdout.String())
	}
}

func githubGraphQLTracePath(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "traces", name))
	if err != nil {
		t.Fatal(err)
	}
	return path
}
