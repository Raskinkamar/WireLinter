package pack

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Raskinkamar/WireLinter/internal/spec"
	"github.com/goccy/go-yaml"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	maxManifestBytes    = 1 << 20
	maxRuleBytes        = 256 << 10
	maxSignatureBytes   = 256 << 10
	maxSecretMatchBytes = 64 << 10
	maxDigestMatchBytes = 64 << 10
	maxSchemaBytes      = 4 << 20
)

type Loader struct {
	spec *spec.Registry
	cel  *celCompiler
}

func NewLoader() (*Loader, error) {
	registry, err := spec.NewRegistry()
	if err != nil {
		return nil, err
	}
	celCompiler, err := newCELCompiler()
	if err != nil {
		return nil, err
	}
	return &Loader{spec: registry, cel: celCompiler}, nil
}

type packSource interface {
	ReadRegular(name string, maxBytes int64) ([]byte, error)
}

type osPackSource struct{ root *os.Root }

func (s osPackSource) ReadRegular(name string, maxBytes int64) ([]byte, error) {
	file, err := s.root.Open(filepath.FromSlash(name))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBoundedRegular(file, name, maxBytes)
}

type fsPackSource struct{ fsys fs.FS }

func (s fsPackSource) ReadRegular(name string, maxBytes int64) ([]byte, error) {
	file, err := s.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBoundedRegular(file, name, maxBytes)
}

func readBoundedRegular(file fs.File, name string, maxBytes int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", name)
	}
	limited := io.LimitReader(file, maxBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%q exceeds %d-byte limit", name, maxBytes)
	}
	return raw, nil
}

func (l *Loader) LoadDir(dir string) (*Loaded, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open provider pack root: %w", err)
	}
	defer root.Close()
	return l.load(osPackSource{root: root})
}

func (l *Loader) LoadFS(fsys fs.FS) (*Loaded, error) {
	if fsys == nil {
		return nil, fmt.Errorf("provider pack filesystem is nil")
	}
	return l.load(fsPackSource{fsys: fsys})
}

func (l *Loader) load(root packSource) (*Loaded, error) {
	manifestRaw, err := root.ReadRegular("pack.yaml", maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("read pack.yaml: %w", err)
	}
	var manifest Manifest
	if err := decodeSingleYAML(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("decode pack.yaml: %w", err)
	}
	if err := l.spec.Validate("pack-v1.schema.json", manifest); err != nil {
		return nil, err
	}

	for name, rel := range manifest.Schemas {
		if _, err := canonicalPackPath(rel); err != nil {
			return nil, fmt.Errorf("schema %q path: %w", name, err)
		}
	}
	for name, rel := range manifest.Signatures {
		if _, err := canonicalPackPath(rel); err != nil {
			return nil, fmt.Errorf("signature %q path: %w", name, err)
		}
	}
	for name, rel := range manifest.SecretMatches {
		if _, err := canonicalPackPath(rel); err != nil {
			return nil, fmt.Errorf("secret match %q path: %w", name, err)
		}
	}
	for name, rel := range manifest.DigestMatches {
		if _, err := canonicalPackPath(rel); err != nil {
			return nil, fmt.Errorf("digest match %q path: %w", name, err)
		}
	}
	for _, rel := range manifest.Rules {
		if _, err := canonicalPackPath(rel); err != nil {
			return nil, fmt.Errorf("rule path %q: %w", rel, err)
		}
	}

	compiledSchemas, err := loadProviderSchemas(root, manifest)
	if err != nil {
		return nil, err
	}
	loadedSignatures, err := l.loadSignatures(root, manifest)
	if err != nil {
		return nil, err
	}
	loadedSecretMatches, err := l.loadSecretMatches(root, manifest)
	if err != nil {
		return nil, err
	}
	loadedDigestMatches, err := l.loadDigestMatches(root, manifest)
	if err != nil {
		return nil, err
	}
	compiledRules, err := l.loadRules(root, manifest, compiledSchemas, loadedSignatures, loadedSecretMatches, loadedDigestMatches)
	if err != nil {
		return nil, err
	}

	return &Loaded{
		Manifest:      manifest,
		Rules:         compiledRules,
		Schemas:       compiledSchemas,
		Signatures:    loadedSignatures,
		SecretMatches: loadedSecretMatches,
		DigestMatches: loadedDigestMatches,
	}, nil
}

func (l *Loader) loadSignatures(root packSource, manifest Manifest) (map[string]SignatureRecipe, error) {
	if len(manifest.Signatures) == 0 {
		return map[string]SignatureRecipe{}, nil
	}
	if !protocolSupportsSignatures(manifest.PackProtocol) {
		return nil, fmt.Errorf("pack protocol %s cannot declare signature recipes", manifest.PackProtocol)
	}
	names := make([]string, 0, len(manifest.Signatures))
	for name := range manifest.Signatures {
		names = append(names, name)
	}
	sort.Strings(names)
	loaded := make(map[string]SignatureRecipe, len(names))
	for _, name := range names {
		rel := manifest.Signatures[name]
		localPath, err := canonicalPackPath(rel)
		if err != nil {
			return nil, fmt.Errorf("signature %q path: %w", name, err)
		}
		raw, err := root.ReadRegular(localPath, maxSignatureBytes)
		if err != nil {
			return nil, fmt.Errorf("read signature %q: %w", name, err)
		}
		var recipe SignatureRecipe
		if err := decodeSingleYAML(raw, &recipe); err != nil {
			return nil, fmt.Errorf("decode signature %q: %w", name, err)
		}
		if err := l.spec.Validate("signature-v1.schema.json", recipe); err != nil {
			return nil, fmt.Errorf("signature %q: %w", name, err)
		}
		if recipe.ID != name {
			return nil, fmt.Errorf("signature manifest key %q must match recipe id %q", name, recipe.ID)
		}
		if err := validateSignatureRecipe(recipe); err != nil {
			return nil, err
		}
		if _, ok := manifest.Secrets[recipe.Secret.Ref]; !ok {
			return nil, fmt.Errorf("signature %q references unknown secret %q", name, recipe.Secret.Ref)
		}
		for _, sourceRef := range recipe.SourceRefs {
			if _, ok := manifest.Docs[sourceRef]; !ok {
				return nil, fmt.Errorf("signature %q references unknown sourceRef %q", name, sourceRef)
			}
		}
		loaded[name] = recipe
	}
	return loaded, nil
}

func (l *Loader) loadSecretMatches(root packSource, manifest Manifest) (map[string]SecretMatchRecipe, error) {
	if len(manifest.SecretMatches) == 0 {
		return map[string]SecretMatchRecipe{}, nil
	}
	if !protocolSupportsSecretMatches(manifest.PackProtocol) {
		return nil, fmt.Errorf("pack protocol %s cannot declare secret-match recipes", manifest.PackProtocol)
	}
	names := make([]string, 0, len(manifest.SecretMatches))
	for name := range manifest.SecretMatches {
		names = append(names, name)
	}
	sort.Strings(names)
	loaded := make(map[string]SecretMatchRecipe, len(names))
	for _, name := range names {
		rel := manifest.SecretMatches[name]
		localPath, err := canonicalPackPath(rel)
		if err != nil {
			return nil, fmt.Errorf("secret match %q path: %w", name, err)
		}
		raw, err := root.ReadRegular(localPath, maxSecretMatchBytes)
		if err != nil {
			return nil, fmt.Errorf("read secret match %q: %w", name, err)
		}
		var recipe SecretMatchRecipe
		if err := decodeSingleYAML(raw, &recipe); err != nil {
			return nil, fmt.Errorf("decode secret match %q: %w", name, err)
		}
		if err := l.spec.Validate("secret-match-v1.schema.json", recipe); err != nil {
			return nil, fmt.Errorf("secret match %q: %w", name, err)
		}
		if recipe.ID != name {
			return nil, fmt.Errorf("secret match manifest key %q must match recipe id %q", name, recipe.ID)
		}
		if _, ok := manifest.Secrets[recipe.Secret.Ref]; !ok {
			return nil, fmt.Errorf("secret match %q references unknown secret %q", name, recipe.Secret.Ref)
		}
		for _, sourceRef := range recipe.SourceRefs {
			if _, ok := manifest.Docs[sourceRef]; !ok {
				return nil, fmt.Errorf("secret match %q references unknown sourceRef %q", name, sourceRef)
			}
		}
		loaded[name] = recipe
	}
	return loaded, nil
}

func (l *Loader) loadDigestMatches(root packSource, manifest Manifest) (map[string]DigestMatchRecipe, error) {
	if len(manifest.DigestMatches) == 0 {
		return map[string]DigestMatchRecipe{}, nil
	}
	if !protocolSupportsDigestMatches(manifest.PackProtocol) {
		return nil, fmt.Errorf("pack protocol %s cannot declare digest-match recipes", manifest.PackProtocol)
	}
	names := make([]string, 0, len(manifest.DigestMatches))
	for name := range manifest.DigestMatches {
		names = append(names, name)
	}
	sort.Strings(names)
	loaded := make(map[string]DigestMatchRecipe, len(names))
	for _, name := range names {
		rel := manifest.DigestMatches[name]
		localPath, err := canonicalPackPath(rel)
		if err != nil {
			return nil, fmt.Errorf("digest match %q path: %w", name, err)
		}
		raw, err := root.ReadRegular(localPath, maxDigestMatchBytes)
		if err != nil {
			return nil, fmt.Errorf("read digest match %q: %w", name, err)
		}
		var recipe DigestMatchRecipe
		if err := decodeSingleYAML(raw, &recipe); err != nil {
			return nil, fmt.Errorf("decode digest match %q: %w", name, err)
		}
		if err := l.spec.Validate("digest-match-v1.schema.json", recipe); err != nil {
			return nil, fmt.Errorf("digest match %q: %w", name, err)
		}
		if recipe.ID != name {
			return nil, fmt.Errorf("digest match manifest key %q must match recipe id %q", name, recipe.ID)
		}
		if err := validateDigestMatchRecipe(recipe); err != nil {
			return nil, err
		}
		if _, ok := manifest.Secrets[recipe.Secret.Ref]; !ok {
			return nil, fmt.Errorf("digest match %q references unknown secret %q", name, recipe.Secret.Ref)
		}
		for _, sourceRef := range recipe.SourceRefs {
			if _, ok := manifest.Docs[sourceRef]; !ok {
				return nil, fmt.Errorf("digest match %q references unknown sourceRef %q", name, sourceRef)
			}
		}
		loaded[name] = recipe
	}
	return loaded, nil
}

func (l *Loader) loadRules(root packSource, manifest Manifest, compiledSchemas map[string]*jsonschema.Schema, signatures map[string]SignatureRecipe, secretMatches map[string]SecretMatchRecipe, digestMatches map[string]DigestMatchRecipe) ([]CompiledRule, error) {
	seenIDs := make(map[string]string, len(manifest.Rules))
	rules := make([]CompiledRule, 0, len(manifest.Rules))
	for _, rel := range manifest.Rules {
		localPath, err := canonicalPackPath(rel)
		if err != nil {
			return nil, fmt.Errorf("rule path %q: %w", rel, err)
		}
		raw, err := root.ReadRegular(localPath, maxRuleBytes)
		if err != nil {
			return nil, fmt.Errorf("read rule %q: %w", rel, err)
		}
		var rule Rule
		if err := decodeSingleYAML(raw, &rule); err != nil {
			return nil, fmt.Errorf("decode rule %q: %w", rel, err)
		}
		if err := l.spec.Validate("rule-v1.schema.json", rule); err != nil {
			return nil, fmt.Errorf("rule %q: %w", rel, err)
		}
		if previous, exists := seenIDs[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate rule id %q in %q and %q", rule.ID, previous, rel)
		}
		seenIDs[rule.ID] = rel
		if _, exists := manifest.Docs[rule.DocsRef]; !exists {
			return nil, fmt.Errorf("rule %q references unknown docsRef %q", rule.ID, rule.DocsRef)
		}
		if rule.Requires != "" && manifest.PackProtocol != "1.2" && manifest.PackProtocol != "1.3" && manifest.PackProtocol != "1.4" {
			return nil, fmt.Errorf("rule %q uses evidence requires, which needs pack protocol 1.2 or newer", rule.ID)
		}
		switch rule.Kind {
		case "json-schema":
			if _, exists := compiledSchemas[rule.SchemaRef]; !exists {
				return nil, fmt.Errorf("rule %q references unknown schemaRef %q", rule.ID, rule.SchemaRef)
			}
		case "signature":
			if !protocolSupportsSignatures(manifest.PackProtocol) {
				return nil, fmt.Errorf("rule %q requires a pack protocol with signature support", rule.ID)
			}
			if _, exists := signatures[rule.SignatureRef]; !exists {
				return nil, fmt.Errorf("rule %q references unknown signatureRef %q", rule.ID, rule.SignatureRef)
			}
		case "secret-match":
			if !protocolSupportsSecretMatches(manifest.PackProtocol) {
				return nil, fmt.Errorf("rule %q requires pack protocol 1.3 or newer secret-match support", rule.ID)
			}
			if _, exists := secretMatches[rule.SecretMatchRef]; !exists {
				return nil, fmt.Errorf("rule %q references unknown secretMatchRef %q", rule.ID, rule.SecretMatchRef)
			}
		case "digest-match":
			if !protocolSupportsDigestMatches(manifest.PackProtocol) {
				return nil, fmt.Errorf("rule %q requires pack protocol 1.4 digest-match support", rule.ID)
			}
			if _, exists := digestMatches[rule.DigestMatchRef]; !exists {
				return nil, fmt.Errorf("rule %q references unknown digestMatchRef %q", rule.ID, rule.DigestMatchRef)
			}
		}

		compiled := CompiledRule{SourcePath: rel, Rule: rule}
		if rule.When != "" {
			program, err := l.cel.compile(manifest.PackProtocol, rule.Scope, rule.When, rule.ID+" when")
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
			}
			compiled.WhenProgram = program
		}
		if rule.Kind == "cel" {
			if rule.Requires != "" {
				program, err := l.cel.compile(manifest.PackProtocol, rule.Scope, rule.Requires, rule.ID+" requires")
				if err != nil {
					return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
				}
				compiled.RequiresProgram = program
			}
			program, err := l.cel.compile(manifest.PackProtocol, rule.Scope, rule.Assert, rule.ID+" assert")
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
			}
			compiled.AssertProgram = program
		}
		rules = append(rules, compiled)
	}
	return rules, nil
}

func protocolSupportsSignatures(protocol string) bool {
	return protocol == "1.1" || protocol == "1.2" || protocol == "1.3" || protocol == "1.4"
}

func protocolSupportsSecretMatches(protocol string) bool {
	return protocol == "1.3" || protocol == "1.4"
}

func protocolSupportsDigestMatches(protocol string) bool {
	return protocol == "1.4"
}

type denyProviderSchemaLoader struct{}

func (denyProviderSchemaLoader) Load(rawURL string) (any, error) {
	return nil, fmt.Errorf("provider schema attempted external resource load: %s", rawURL)
}

func loadProviderSchemas(root packSource, manifest Manifest) (map[string]*jsonschema.Schema, error) {
	if len(manifest.Schemas) == 0 {
		return map[string]*jsonschema.Schema{}, nil
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiler.AssertContent()
	compiler.UseLoader(denyProviderSchemaLoader{})
	names := make([]string, 0, len(manifest.Schemas))
	for name := range manifest.Schemas {
		names = append(names, name)
	}
	sort.Strings(names)
	locations := make(map[string]string, len(names))
	for _, name := range names {
		rel := manifest.Schemas[name]
		localPath, err := canonicalPackPath(rel)
		if err != nil {
			return nil, fmt.Errorf("schema %q path: %w", name, err)
		}
		raw, err := root.ReadRegular(localPath, maxSchemaBytes)
		if err != nil {
			return nil, fmt.Errorf("read schema %q: %w", name, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("parse provider schema %q: %w", name, err)
		}
		location := "https://packs.wirelint.invalid/" + manifest.ID + "/" + rel
		if err := compiler.AddResource(location, doc); err != nil {
			return nil, fmt.Errorf("register provider schema %q: %w", name, err)
		}
		locations[name] = location
	}
	compiled := make(map[string]*jsonschema.Schema, len(names))
	for _, name := range names {
		schema, err := compiler.Compile(locations[name])
		if err != nil {
			return nil, fmt.Errorf("compile provider schema %q: %w", name, err)
		}
		compiled[name] = schema
	}
	return compiled, nil
}

func decodeSingleYAML(raw []byte, out any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw), yaml.Strict())
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return fmt.Errorf("multiple YAML documents are not allowed")
	} else if err != io.EOF {
		return fmt.Errorf("read trailing YAML document: %w", err)
	}
	return nil
}

func canonicalPackPath(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("path is empty")
	}
	if strings.Contains(raw, "\\") {
		return "", fmt.Errorf("backslashes are not allowed; pack paths use forward slashes")
	}
	clean := path.Clean(raw)
	if clean != raw || clean == "." || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("path must be canonical and relative: %q", raw)
	}
	for _, part := range strings.Split(clean, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("path contains forbidden segment %q", part)
		}
	}
	return clean, nil
}
