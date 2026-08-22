package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Raskinkamar/WireLinter/internal/spec"
)

func TestReferenceSignatureRecipesFitOneSchemaAndSemanticModel(t *testing.T) {
	files := []string{
		"stripe-v1.yaml",
		"shopify.yaml",
		"github.yaml",
		"mercadopago.yaml",
		"standard-webhooks.yaml",
	}
	registry, err := spec.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range files {
		t.Run(name, func(t *testing.T) {
			recipe := readSignatureFixture(t, name)
			if err := registry.Validate("signature-v1.schema.json", recipe); err != nil {
				t.Fatalf("reference recipe violates signature schema: %v", err)
			}
			if err := validateSignatureRecipe(recipe); err != nil {
				t.Fatalf("reference recipe violates semantic model: %v", err)
			}
		})
	}
}

func TestMercadoPagoRecipePreservesCaseByConstruction(t *testing.T) {
	recipe := readSignatureFixture(t, "mercadopago.yaml")
	binding := recipe.Bindings["data-id"]
	if binding.FromQuery == nil || binding.FromQuery.Name != "data.id" || !binding.FromQuery.TrimSpace {
		t.Fatalf("unexpected Mercado Pago data-id binding: %#v", binding)
	}
	// Protocol 1.1 deliberately has no lowercase/uppercase transform. If case
	// normalization is ever added, this fixture must remain an explicit
	// compatibility test for the June 2026 Mercado Pago SDK behavior change.
}

func TestStripeFreshnessMatchesCurrentSDKAgeSemantics(t *testing.T) {
	recipe := readSignatureFixture(t, "stripe-v1.yaml")
	if recipe.Freshness == nil || recipe.Freshness.MaxAgeSeconds == nil {
		t.Fatalf("Stripe recipe must enforce max age: %#v", recipe.Freshness)
	}
	if recipe.Freshness.MaxFutureSeconds != nil {
		t.Fatalf("Stripe recipe must not invent a future bound absent from current Go/Node validators: %#v", recipe.Freshness)
	}
}

func TestStandardWebhooksFreshnessIsBidirectional(t *testing.T) {
	recipe := readSignatureFixture(t, "standard-webhooks.yaml")
	if recipe.Freshness == nil || recipe.Freshness.MaxAgeSeconds == nil || recipe.Freshness.MaxFutureSeconds == nil {
		t.Fatalf("Standard Webhooks reference behavior requires old and future bounds: %#v", recipe.Freshness)
	}
}

func TestSignatureRecipeRejectsUnknownParserReference(t *testing.T) {
	recipe := readSignatureFixture(t, "stripe-v1.yaml")
	binding := recipe.Bindings["timestamp"]
	binding.FromField.Parser = "missing-parser"
	recipe.Bindings["timestamp"] = binding
	assertSignatureSemanticError(t, recipe, "unknown parser")
}

func TestSignatureRecipeRejectsParserSourceWithImplicitMergeSemantics(t *testing.T) {
	recipe := readSignatureFixture(t, "stripe-v1.yaml")
	parser := recipe.Parsers["signature-fields"]
	parser.SourceHeader.Cardinality = "one-or-more"
	recipe.Parsers["signature-fields"] = parser
	assertSignatureSemanticError(t, recipe, "source header must be exactly-one")
}

func TestSignatureRecipeRejectsOptionalMessageBindingWithoutOmit(t *testing.T) {
	recipe := readSignatureFixture(t, "mercadopago.yaml")
	for i := range recipe.Message {
		if recipe.Message[i].Binding == "data-id" {
			recipe.Message[i].OmitIfAbsent = false
		}
	}
	assertSignatureSemanticError(t, recipe, "must set omitIfAbsent")
}

func TestSignatureRecipeRejectsRequiredMessageBindingWithOmit(t *testing.T) {
	recipe := readSignatureFixture(t, "stripe-v1.yaml")
	for i := range recipe.Message {
		if recipe.Message[i].Binding == "timestamp" {
			recipe.Message[i].OmitIfAbsent = true
		}
	}
	assertSignatureSemanticError(t, recipe, "cannot set omitIfAbsent")
}

func TestSignatureRecipeRejectsListBindingInMessage(t *testing.T) {
	recipe := readSignatureFixture(t, "stripe-v1.yaml")
	recipe.Message = append(recipe.Message, SignatureMessageSegment{Binding: "signature-candidates"})
	assertSignatureSemanticError(t, recipe, "list cardinality")
}

func TestSignatureRecipeRejectsOptionalCandidates(t *testing.T) {
	recipe := readSignatureFixture(t, "shopify.yaml")
	binding := recipe.Bindings["signature-candidates"]
	binding.FromHeader.Cardinality = "zero-or-one"
	recipe.Bindings["signature-candidates"] = binding
	assertSignatureSemanticError(t, recipe, "cannot be optional")
}

func TestSignatureRecipeRejectsListFreshnessTimestamp(t *testing.T) {
	recipe := readSignatureFixture(t, "stripe-v1.yaml")
	recipe.Freshness.TimestampBinding = "signature-candidates"
	assertSignatureSemanticError(t, recipe, "must be exactly-one")
}

func TestSignatureRecipeRejectsAmbiguousParserDelimiters(t *testing.T) {
	recipe := readSignatureFixture(t, "stripe-v1.yaml")
	parser := recipe.Parsers["signature-fields"]
	parser.Format.PairDelimiter = parser.Format.ItemDelimiter
	recipe.Parsers["signature-fields"] = parser
	assertSignatureSemanticError(t, recipe, "same item and pair delimiter")
}

func readSignatureFixture(t *testing.T, name string) SignatureRecipe {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "signatures", name))
	if err != nil {
		t.Fatal(err)
	}
	var recipe SignatureRecipe
	if err := decodeSingleYAML(raw, &recipe); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return recipe
}

func assertSignatureSemanticError(t *testing.T, recipe SignatureRecipe, contains string) {
	t.Helper()
	err := validateSignatureRecipe(recipe)
	if err == nil {
		t.Fatalf("expected semantic validation failure containing %q", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not contain %q", err, contains)
	}
}
