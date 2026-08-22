package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

func styledReportFixture() model.Report {
	return model.Report{
		TraceID:  "trace_demo",
		Provider: "meta-whatsapp-webhooks",
		Pack: &model.PackIdentity{
			ID:       "meta-whatsapp-webhooks",
			Version:  "0.1.0",
			Protocol: "1.2",
		},
		Results: []model.RuleResult{
			{RuleID: "WL-META-METHOD-001", Kind: "pass", Title: "method", Message: "ok"},
			{RuleID: "WL-META-SIGNATURE-001", Kind: "fail", Level: "error", Title: "signature", MessageID: "signature-mismatch", Message: "signature does not match", DocsRef: &model.DocsRef{URL: "https://example.test/docs"}},
		},
		Summary: model.ReportSummary{Pass: 1, Fail: 1, Errors: 1},
	}
}

func TestStyledReportIsPlainWhenNotWritingToTTY(t *testing.T) {
	t.Setenv("WIRELINT_COLOR", "auto")
	var out bytes.Buffer
	writeStyledTextReport(&out, styledReportFixture())

	text := out.String()
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("non-TTY output must not contain ANSI escapes: %q", text)
	}
	for _, want := range []string{"WIRELINT", "PASS", "FAIL/ERROR", "signature-mismatch", "1 passed", "1 failed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in report:\n%s", want, text)
		}
	}
}

func TestStyledReportCanForceColor(t *testing.T) {
	t.Setenv("WIRELINT_COLOR", "always")
	var out bytes.Buffer
	writeStyledTextReport(&out, styledReportFixture())
	if !strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("WIRELINT_COLOR=always should emit ANSI escapes")
	}
}

func TestStyledReportRespectsNoColor(t *testing.T) {
	t.Setenv("WIRELINT_COLOR", "always")
	t.Setenv("NO_COLOR", "1")
	var out bytes.Buffer
	writeStyledTextReport(&out, styledReportFixture())
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("NO_COLOR must disable ANSI escapes")
	}
}
