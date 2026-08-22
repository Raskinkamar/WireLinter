package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveIntegrationHumanAliases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "mercadopago", want: "mercadopago-webhooks"},
		{input: "Mercado Pago", want: "mercadopago-webhooks"},
		{input: "whatsapp", want: "meta-whatsapp-webhooks"},
		{input: "whatsapp verification", want: "meta-whatsapp-webhook-verification"},
		{input: "whatsapp api", want: "meta-whatsapp-cloud-api"},
		{input: "github api", want: "github-graphql-api"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			matches, err := resolveIntegration(tt.input)
			if err != nil {
				t.Fatalf("resolveIntegration() error = %v", err)
			}
			if len(matches) != 1 {
				t.Fatalf("resolveIntegration() returned %d matches, want 1", len(matches))
			}
			if matches[0].ID != tt.want {
				t.Fatalf("resolveIntegration() id = %q, want %q", matches[0].ID, tt.want)
			}
		})
	}
}

func TestRunInteractiveNoArgsExplainsTheNextStepOnEOF(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := RunInteractive(nil, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunInteractive() code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{
		"WIRELINT",
		"Integration (try mercadopago, whatsapp, stripe):",
		"wirelint mercadopago http://localhost:8000/webhook",
		"wirelint integrations",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout does not contain %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunInteractiveMercadoPagoAliasLintsSavedCapture(t *testing.T) {
	t.Setenv("MERCADOPAGO_WEBHOOK_SECRET", "mp_wirelint_demo_secret")
	trace := filepath.Join("..", "..", "examples", "traces", "mercadopago-webhooks-valid.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := RunInteractive([]string{"mercadopago", trace}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunInteractive() code = %d, stderr = %s\nstdout = %s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "mercadopago-webhooks") {
		t.Fatalf("stdout does not identify Mercado Pago pack:\n%s", stdout.String())
	}
}

func TestIntegrationKindAndURLDetection(t *testing.T) {
	inbound := integrationChoice{ID: "mercadopago-webhooks", Name: "Mercado Pago Webhooks"}
	if got := inferIntegrationKind(inbound); got != integrationInbound {
		t.Fatalf("inferIntegrationKind(inbound) = %v, want inbound", got)
	}

	outbound := integrationChoice{ID: "github-graphql-api", Name: "GitHub GraphQL API"}
	if got := inferIntegrationKind(outbound); got != integrationOutbound {
		t.Fatalf("inferIntegrationKind(outbound) = %v, want outbound", got)
	}

	for _, value := range []string{"http://localhost:8000/webhook", "https://api.github.com"} {
		if !looksLikeHTTPURL(value) {
			t.Fatalf("looksLikeHTTPURL(%q) = false", value)
		}
	}
	for _, value := range []string{"trace.json", "localhost:8000/webhook", ""} {
		if looksLikeHTTPURL(value) {
			t.Fatalf("looksLikeHTTPURL(%q) = true", value)
		}
	}
}

func TestFriendlyIntegrationsCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := RunInteractive([]string{"integrations", "--region", "BR"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("RunInteractive() code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "WIRELINT / integrations") {
		t.Fatalf("stdout missing integrations header:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Mercado Pago") {
		t.Fatalf("stdout missing a Brazilian integration:\n%s", stdout.String())
	}
}
