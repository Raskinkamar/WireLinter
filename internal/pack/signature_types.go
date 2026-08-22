package pack

import "fmt"

type SignatureRecipe struct {
	SchemaVersion int                         `json:"schemaVersion" yaml:"schemaVersion"`
	ID            string                      `json:"id" yaml:"id"`
	SourceRefs    []string                    `json:"sourceRefs" yaml:"sourceRefs"`
	Secret        SignatureSecret             `json:"secret" yaml:"secret"`
	Parsers       map[string]SignatureParser  `json:"parsers,omitempty" yaml:"parsers,omitempty"`
	Bindings      map[string]SignatureBinding `json:"bindings" yaml:"bindings"`
	Message       []SignatureMessageSegment   `json:"message" yaml:"message"`
	Candidates    SignatureCandidates         `json:"candidates" yaml:"candidates"`
	MAC           SignatureMAC                `json:"mac" yaml:"mac"`
	Freshness     *SignatureFreshness          `json:"freshness,omitempty" yaml:"freshness,omitempty"`
	Metadata      map[string]any               `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

type SignatureSecret struct {
	Ref            string `json:"ref" yaml:"ref"`
	Representation string `json:"representation" yaml:"representation"`
	Prefix         string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
}

type SignatureParser struct {
	SourceHeader SignatureParserHeaderSource `json:"sourceHeader" yaml:"sourceHeader"`
	Format       SignatureParserFormat       `json:"format" yaml:"format"`
}

type SignatureParserHeaderSource struct {
	Name        string `json:"name" yaml:"name"`
	Cardinality string `json:"cardinality" yaml:"cardinality"`
	TrimSpace   bool   `json:"trimSpace,omitempty" yaml:"trimSpace,omitempty"`
}

type SignatureParserFormat struct {
	Type          string `json:"type" yaml:"type"`
	ItemDelimiter string `json:"itemDelimiter" yaml:"itemDelimiter"`
	PairDelimiter string `json:"pairDelimiter" yaml:"pairDelimiter"`
	TrimSpace     bool   `json:"trimSpace" yaml:"trimSpace"`
}

type SignatureBinding struct {
	FromRawBody *SignatureRawBodySource `json:"fromRawBody,omitempty" yaml:"fromRawBody,omitempty"`
	FromHeader  *SignatureHeaderSource  `json:"fromHeader,omitempty" yaml:"fromHeader,omitempty"`
	FromQuery   *SignatureQuerySource   `json:"fromQuery,omitempty" yaml:"fromQuery,omitempty"`
	FromField   *SignatureFieldSource   `json:"fromField,omitempty" yaml:"fromField,omitempty"`
}

type SignatureRawBodySource struct {
	RequireFidelity string `json:"requireFidelity" yaml:"requireFidelity"`
}

type SignatureHeaderSource struct {
	Name        string `json:"name" yaml:"name"`
	Cardinality string `json:"cardinality" yaml:"cardinality"`
	TrimSpace   bool   `json:"trimSpace,omitempty" yaml:"trimSpace,omitempty"`
}

type SignatureQuerySource struct {
	Name        string `json:"name" yaml:"name"`
	Cardinality string `json:"cardinality" yaml:"cardinality"`
	TrimSpace   bool   `json:"trimSpace,omitempty" yaml:"trimSpace,omitempty"`
}

type SignatureFieldSource struct {
	Parser      string `json:"parser" yaml:"parser"`
	Key         string `json:"key" yaml:"key"`
	Cardinality string `json:"cardinality" yaml:"cardinality"`
}

type SignatureMessageSegment struct {
	Literal      *string `json:"literal,omitempty" yaml:"literal,omitempty"`
	Binding      string  `json:"binding,omitempty" yaml:"binding,omitempty"`
	Prefix       string  `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	Suffix       string  `json:"suffix,omitempty" yaml:"suffix,omitempty"`
	OmitIfAbsent bool    `json:"omitIfAbsent,omitempty" yaml:"omitIfAbsent,omitempty"`
}

type SignatureCandidates struct {
	Binding     string `json:"binding" yaml:"binding"`
	Encoding    string `json:"encoding" yaml:"encoding"`
	StripPrefix string `json:"stripPrefix,omitempty" yaml:"stripPrefix,omitempty"`
}

type SignatureMAC struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
}

type SignatureFreshness struct {
	TimestampBinding string `json:"timestampBinding" yaml:"timestampBinding"`
	Format           string `json:"format" yaml:"format"`
	Reference        string `json:"reference" yaml:"reference"`
	MaxAgeSeconds    *int   `json:"maxAgeSeconds,omitempty" yaml:"maxAgeSeconds,omitempty"`
	MaxFutureSeconds *int   `json:"maxFutureSeconds,omitempty" yaml:"maxFutureSeconds,omitempty"`
}

func validateSignatureRecipe(recipe SignatureRecipe) error {
	for name, binding := range recipe.Bindings {
		if err := validateSignatureBinding(name, binding, recipe.Parsers); err != nil {
			return err
		}
	}

	for i, segment := range recipe.Message {
		if segment.Literal != nil {
			continue
		}
		binding, ok := recipe.Bindings[segment.Binding]
		if !ok {
			return fmt.Errorf("signature %s message segment %d references unknown binding %q", recipe.ID, i, segment.Binding)
		}
		cardinality, isList, optional := signatureBindingShape(binding)
		if isList {
			return fmt.Errorf("signature %s message segment %d binding %q has list cardinality %q", recipe.ID, i, segment.Binding, cardinality)
		}
		if optional != segment.OmitIfAbsent {
			if optional {
				return fmt.Errorf("signature %s optional message binding %q must set omitIfAbsent", recipe.ID, segment.Binding)
			}
			return fmt.Errorf("signature %s required message binding %q cannot set omitIfAbsent", recipe.ID, segment.Binding)
		}
	}

	candidate, ok := recipe.Bindings[recipe.Candidates.Binding]
	if !ok {
		return fmt.Errorf("signature %s candidates reference unknown binding %q", recipe.ID, recipe.Candidates.Binding)
	}
	if candidate.FromRawBody != nil {
		return fmt.Errorf("signature %s candidates binding %q cannot be raw body bytes", recipe.ID, recipe.Candidates.Binding)
	}
	cardinality, _, optional := signatureBindingShape(candidate)
	if optional {
		return fmt.Errorf("signature %s candidates binding %q cannot be optional (%s)", recipe.ID, recipe.Candidates.Binding, cardinality)
	}

	if recipe.Freshness != nil {
		binding, ok := recipe.Bindings[recipe.Freshness.TimestampBinding]
		if !ok {
			return fmt.Errorf("signature %s freshness references unknown binding %q", recipe.ID, recipe.Freshness.TimestampBinding)
		}
		if binding.FromRawBody != nil {
			return fmt.Errorf("signature %s freshness timestamp binding %q cannot be raw bytes", recipe.ID, recipe.Freshness.TimestampBinding)
		}
		cardinality, isList, optional := signatureBindingShape(binding)
		if isList || optional || cardinality != "exactly-one" {
			return fmt.Errorf("signature %s freshness timestamp binding %q must be exactly-one", recipe.ID, recipe.Freshness.TimestampBinding)
		}
	}

	for name, parser := range recipe.Parsers {
		if parser.SourceHeader.Cardinality != "exactly-one" {
			return fmt.Errorf("signature %s parser %q source header must be exactly-one", recipe.ID, name)
		}
		if parser.Format.ItemDelimiter == parser.Format.PairDelimiter {
			return fmt.Errorf("signature %s parser %q uses the same item and pair delimiter", recipe.ID, name)
		}
	}
	return nil
}

func validateSignatureBinding(name string, binding SignatureBinding, parsers map[string]SignatureParser) error {
	count := 0
	if binding.FromRawBody != nil {
		count++
	}
	if binding.FromHeader != nil {
		count++
	}
	if binding.FromQuery != nil {
		count++
	}
	if binding.FromField != nil {
		count++
		if _, ok := parsers[binding.FromField.Parser]; !ok {
			return fmt.Errorf("signature binding %q references unknown parser %q", name, binding.FromField.Parser)
		}
	}
	if count != 1 {
		return fmt.Errorf("signature binding %q must declare exactly one source, got %d", name, count)
	}
	return nil
}

func signatureBindingShape(binding SignatureBinding) (cardinality string, isList bool, optional bool) {
	if binding.FromRawBody != nil {
		return "exactly-one", false, false
	}
	if binding.FromHeader != nil {
		cardinality = binding.FromHeader.Cardinality
	} else if binding.FromQuery != nil {
		cardinality = binding.FromQuery.Cardinality
	} else if binding.FromField != nil {
		cardinality = binding.FromField.Cardinality
	}
	return cardinality, cardinality == "one-or-more", cardinality == "zero-or-one"
}
