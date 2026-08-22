package spec

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Raskinkamar/WireLinter/schemas"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaBase = "https://wirelint.dev/schemas/"

var publicSchemas = []string{
	"trace-v1.schema.json",
	"report-v1.schema.json",
	"pack-v1.schema.json",
	"rule-v1.schema.json",
	"signature-v1.schema.json",
	"secret-match-v1.schema.json",
	"digest-match-v1.schema.json",
}

type denyLoader struct{}

func (denyLoader) Load(rawURL string) (any, error) {
	return nil, fmt.Errorf("external schema loading is disabled: %s", rawURL)
}

type Registry struct {
	compiled map[string]*jsonschema.Schema
}

func NewRegistry() (*Registry, error) {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.AssertContent()
	compiler.UseLoader(denyLoader{})

	for _, name := range publicSchemas {
		raw, err := schemas.Read(name)
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("parse embedded schema %s: %w", name, err)
		}
		if err := compiler.AddResource(schemaBase+name, doc); err != nil {
			return nil, fmt.Errorf("register embedded schema %s: %w", name, err)
		}
	}

	registry := &Registry{compiled: make(map[string]*jsonschema.Schema, len(publicSchemas))}
	for _, name := range publicSchemas {
		schema, err := compiler.Compile(schemaBase + name)
		if err != nil {
			return nil, fmt.Errorf("compile embedded schema %s: %w", name, err)
		}
		registry.compiled[name] = schema
	}
	return registry, nil
}

func (r *Registry) Validate(schemaName string, value any) error {
	schema, ok := r.compiled[schemaName]
	if !ok {
		return fmt.Errorf("unknown WireLinter schema %q", schemaName)
	}
	jsonValue, err := NormalizeJSON(value)
	if err != nil {
		return err
	}
	if err := schema.Validate(jsonValue); err != nil {
		return fmt.Errorf("validate %s: %w", schemaName, err)
	}
	return nil
}

func NormalizeJSON(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON-compatible value: %w", err)
	}
	jsonValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("normalize JSON-compatible value: %w", err)
	}
	return jsonValue, nil
}

func NormalizeCEL(value any) (any, error) {
	normalized, err := NormalizeJSON(value)
	if err != nil {
		return nil, err
	}
	return normalizeCELValue(normalized, "$")
}

func normalizeCELValue(value any, path string) (any, error) {
	switch typed := value.(type) {
	case nil, bool:
		return typed, nil
	case string:
		if isRawBodyBytesPath(path) {
			decoded, err := base64.StdEncoding.DecodeString(typed)
			if err != nil {
				return nil, fmt.Errorf("%s: decode raw body base64 for CEL bytes: %w", path, err)
			}
			return decoded, nil
		}
		return typed, nil
	case json.Number:
		return normalizeCELNumber(typed, path)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			converted, err := normalizeCELValue(item, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			converted, err := normalizeCELValue(item, path+"."+key)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: unsupported normalized JSON value %T", path, value)
	}
}

func isRawBodyBytesPath(path string) bool {
	return strings.HasSuffix(path, ".request.rawBodyBase64") || strings.HasSuffix(path, ".response.rawBodyBase64")
}

func normalizeCELNumber(number json.Number, path string) (any, error) {
	raw := number.String()
	if !strings.ContainsAny(raw, ".eE") {
		integer, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: JSON integer %q is outside CEL int64 range: %w", path, raw, err)
		}
		return integer, nil
	}

	double, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil, fmt.Errorf("%s: JSON number %q is outside CEL double range: %w", path, raw, err)
	}
	if math.IsInf(double, 0) || math.IsNaN(double) {
		return nil, fmt.Errorf("%s: JSON number %q is not a finite CEL double", path, raw)
	}
	return double, nil
}
