package engine

import (
	"errors"
	"fmt"

	digestcheck "github.com/Raskinkamar/WireLinter/internal/digestmatch"
	"github.com/Raskinkamar/WireLinter/internal/jsonpointer"
	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
	secretcheck "github.com/Raskinkamar/WireLinter/internal/secretmatch"
	sigcheck "github.com/Raskinkamar/WireLinter/internal/signature"
	"github.com/Raskinkamar/WireLinter/internal/spec"
	"github.com/google/cel-go/cel"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type SecretResolver interface {
	Lookup(ref string) (value string, ok bool, err error)
}

type Evaluator struct {
	spec    *spec.Registry
	secrets SecretResolver
}

func New() (*Evaluator, error) {
	return NewWithSecrets(nil)
}

func NewWithSecrets(secrets SecretResolver) (*Evaluator, error) {
	registry, err := spec.NewRegistry()
	if err != nil {
		return nil, err
	}
	return &Evaluator{spec: registry, secrets: secrets}, nil
}

func (e *Evaluator) Evaluate(trace model.Trace, loaded *pack.Loaded) (model.Report, error) {
	if loaded == nil {
		return model.Report{}, fmt.Errorf("evaluate: provider pack is nil")
	}
	if err := e.spec.Validate("trace-v1.schema.json", trace); err != nil {
		return model.Report{}, fmt.Errorf("evaluate trace: %w", err)
	}
	if trace.Provider != loaded.Manifest.ID {
		return model.Report{}, fmt.Errorf("trace provider %q does not match pack %q", trace.Provider, loaded.Manifest.ID)
	}
	for i, envelope := range trace.Envelopes {
		if envelope.Provider != trace.Provider {
			return model.Report{}, fmt.Errorf("envelope %d provider %q does not match trace provider %q", i, envelope.Provider, trace.Provider)
		}
	}

	jsonNormalized, err := spec.NormalizeJSON(trace)
	if err != nil {
		return model.Report{}, fmt.Errorf("normalize trace for JSON evidence: %w", err)
	}
	traceRoot, ok := jsonNormalized.(map[string]any)
	if !ok {
		return model.Report{}, fmt.Errorf("normalize JSON trace: expected object root, got %T", jsonNormalized)
	}
	envelopesRaw, ok := traceRoot["envelopes"].([]any)
	if !ok {
		return model.Report{}, fmt.Errorf("normalize JSON trace: envelopes are %T, expected array", traceRoot["envelopes"])
	}
	if len(envelopesRaw) != len(trace.Envelopes) {
		return model.Report{}, fmt.Errorf("normalize JSON trace: envelope count changed from %d to %d", len(trace.Envelopes), len(envelopesRaw))
	}

	celNormalized, err := spec.NormalizeCEL(trace)
	if err != nil {
		return model.Report{}, fmt.Errorf("normalize trace for CEL: %w", err)
	}
	celTraceRoot, ok := celNormalized.(map[string]any)
	if !ok {
		return model.Report{}, fmt.Errorf("normalize CEL trace: expected object root, got %T", celNormalized)
	}
	celEnvelopesRaw, ok := celTraceRoot["envelopes"].([]any)
	if !ok {
		return model.Report{}, fmt.Errorf("normalize CEL trace: envelopes are %T, expected array", celTraceRoot["envelopes"])
	}
	if len(celEnvelopesRaw) != len(trace.Envelopes) {
		return model.Report{}, fmt.Errorf("normalize CEL trace: envelope count changed from %d to %d", len(trace.Envelopes), len(celEnvelopesRaw))
	}

	report := model.Report{SchemaVersion: 1, TraceID: trace.TraceID, Provider: trace.Provider, Pack: &model.PackIdentity{ID: loaded.Manifest.ID, Version: loaded.Manifest.PackVersion, Protocol: loaded.Manifest.PackProtocol, ProviderDocsRevision: loaded.Manifest.ProviderDocsRevision}, Results: []model.RuleResult{}}
	for _, compiled := range loaded.Rules {
		switch compiled.Rule.Scope {
		case "trace":
			result, err := e.evaluateRule(compiled, loaded, trace.TraceID, "", -1, traceRoot, celTraceRoot, nil)
			if err != nil {
				return model.Report{}, err
			}
			report.Results = append(report.Results, result)
		case "envelope":
			for i, envelopeRaw := range envelopesRaw {
				envelopeRoot, ok := envelopeRaw.(map[string]any)
				if !ok {
					return model.Report{}, fmt.Errorf("rule %s: JSON envelope %d normalized to %T, expected object", compiled.Rule.ID, i, envelopeRaw)
				}
				celEnvelopeRoot, ok := celEnvelopesRaw[i].(map[string]any)
				if !ok {
					return model.Report{}, fmt.Errorf("rule %s: CEL envelope %d normalized to %T, expected object", compiled.Rule.ID, i, celEnvelopesRaw[i])
				}
				result, err := e.evaluateRule(compiled, loaded, trace.TraceID, trace.Envelopes[i].ID, i, envelopeRoot, celEnvelopeRoot, &trace.Envelopes[i])
				if err != nil {
					return model.Report{}, err
				}
				report.Results = append(report.Results, result)
			}
		default:
			return model.Report{}, fmt.Errorf("rule %s: unsupported scope %q", compiled.Rule.ID, compiled.Rule.Scope)
		}
	}
	for _, result := range report.Results {
		switch result.Kind {
		case "pass":
			report.Summary.Pass++
		case "fail":
			report.Summary.Fail++
			switch result.Level {
			case "error":
				report.Summary.Errors++
			case "warning":
				report.Summary.Warnings++
			case "note":
				report.Summary.Notes++
			default:
				return model.Report{}, fmt.Errorf("failed result %s has unsupported level %q", result.RuleID, result.Level)
			}
		case "open":
			report.Summary.Open++
		case "notApplicable":
			report.Summary.NotApplicable++
		default:
			return model.Report{}, fmt.Errorf("result %s has unsupported kind %q", result.RuleID, result.Kind)
		}
	}
	if err := e.spec.Validate("report-v1.schema.json", report); err != nil {
		return model.Report{}, fmt.Errorf("generated report violates public contract: %w", err)
	}
	return report, nil
}

func (e *Evaluator) evaluateRule(compiled pack.CompiledRule, loaded *pack.Loaded, traceID, envelopeID string, envelopeIndex int, root, celRoot map[string]any, envelope *model.Envelope) (model.RuleResult, error) {
	rule := compiled.Rule
	doc, ok := loaded.Manifest.Docs[rule.DocsRef]
	if !ok {
		return model.RuleResult{}, fmt.Errorf("rule %s docsRef %q disappeared after pack load", rule.ID, rule.DocsRef)
	}
	subjectPointer := ""
	if rule.Scope == "envelope" {
		subjectPointer = envelopePointer(envelopeIndex, "")
	}
	result := model.RuleResult{RuleID: rule.ID, Kind: "pass", Level: "none", Stability: rule.Stability, Provider: loaded.Manifest.ID, Title: rule.Title, Message: "Rule evaluated successfully and no problem was found.", SubjectRef: model.EvidenceRef{TraceID: traceID, EnvelopeID: envelopeID, JSONPointer: subjectPointer}, DocsRef: &model.DocsRef{URL: doc.URL, Revision: doc.Revision, Section: doc.Section}, RemediationKey: rule.RemediationKey}
	activation := map[string]any{"provider": loaded.Manifest.ID}
	if rule.Scope == "trace" {
		activation["trace"] = celRoot
	} else {
		activation["envelope"] = celRoot
	}
	if compiled.WhenProgram != nil {
		applies, err := evalBool(compiled.WhenProgram, activation)
		if err != nil {
			return model.RuleResult{}, fmt.Errorf("rule %s when evaluation: %w", rule.ID, err)
		}
		if !applies {
			result.Kind = "notApplicable"
			result.Message = "Rule does not apply to this evidence."
			return result, nil
		}
	}
	if compiled.RequiresProgram != nil {
		sufficient, err := evalBool(compiled.RequiresProgram, activation)
		if err != nil {
			return model.RuleResult{}, fmt.Errorf("rule %s requires evaluation: %w", rule.ID, err)
		}
		if !sufficient {
			result.Kind = "open"
			result.MessageID = "evidence-unavailable"
			result.Message = "Available evidence is insufficient to decide this rule safely."
			if override := rule.Messages[result.MessageID]; override != "" {
				result.Message = override
			}
			result.EvidenceRefs = []model.EvidenceRef{result.SubjectRef}
			return result, nil
		}
	}
	if rule.Kind == "signature" {
		if envelope == nil {
			return model.RuleResult{}, fmt.Errorf("rule %s is a signature rule without envelope evidence", rule.ID)
		}
		recipe, ok := loaded.Signatures[rule.SignatureRef]
		if !ok {
			return model.RuleResult{}, fmt.Errorf("rule %s signatureRef %q disappeared after pack load", rule.ID, rule.SignatureRef)
		}
		outcome, err := sigcheck.Evaluate(recipe, *envelope, e.secrets)
		if err != nil {
			return model.RuleResult{}, fmt.Errorf("rule %s signature evaluation: %w", rule.ID, err)
		}
		return applyTrustedOutcome(result, rule, traceID, envelopeID, envelopeIndex, root, outcome.Kind, outcome.MessageID, outcome.Message, outcome.EvidencePointers, outcome.Metadata)
	}
	if rule.Kind == "secret-match" {
		if envelope == nil {
			return model.RuleResult{}, fmt.Errorf("rule %s is a secret-match rule without envelope evidence", rule.ID)
		}
		recipe, ok := loaded.SecretMatches[rule.SecretMatchRef]
		if !ok {
			return model.RuleResult{}, fmt.Errorf("rule %s secretMatchRef %q disappeared after pack load", rule.ID, rule.SecretMatchRef)
		}
		outcome, err := secretcheck.Evaluate(recipe, *envelope, e.secrets)
		if err != nil {
			return model.RuleResult{}, fmt.Errorf("rule %s secret-match evaluation: %w", rule.ID, err)
		}
		return applyTrustedOutcome(result, rule, traceID, envelopeID, envelopeIndex, root, outcome.Kind, outcome.MessageID, outcome.Message, outcome.EvidencePointers, outcome.Metadata)
	}
	if rule.Kind == "digest-match" {
		if envelope == nil {
			return model.RuleResult{}, fmt.Errorf("rule %s is a digest-match rule without envelope evidence", rule.ID)
		}
		recipe, ok := loaded.DigestMatches[rule.DigestMatchRef]
		if !ok {
			return model.RuleResult{}, fmt.Errorf("rule %s digestMatchRef %q disappeared after pack load", rule.ID, rule.DigestMatchRef)
		}
		outcome, err := digestcheck.Evaluate(recipe, *envelope, e.secrets)
		if err != nil {
			return model.RuleResult{}, fmt.Errorf("rule %s digest-match evaluation: %w", rule.ID, err)
		}
		return applyTrustedOutcome(result, rule, traceID, envelopeID, envelopeIndex, root, outcome.Kind, outcome.MessageID, outcome.Message, outcome.EvidencePointers, outcome.Metadata)
	}

	violated := false
	metadata := map[string]any(nil)
	switch rule.Kind {
	case "cel":
		passed, err := evalBool(compiled.AssertProgram, activation)
		if err != nil {
			return model.RuleResult{}, fmt.Errorf("rule %s assertion evaluation: %w", rule.ID, err)
		}
		violated = !passed
	case "json-schema":
		target, err := jsonpointer.Resolve(root, rule.TargetPointer)
		if err != nil {
			return model.RuleResult{}, fmt.Errorf("rule %s targetPointer %q: %w", rule.ID, rule.TargetPointer, err)
		}
		schema := loaded.Schemas[rule.SchemaRef]
		if schema == nil {
			return model.RuleResult{}, fmt.Errorf("rule %s schemaRef %q is not compiled", rule.ID, rule.SchemaRef)
		}
		if err := schema.Validate(target); err != nil {
			var validation *jsonschema.ValidationError
			if !errors.As(err, &validation) {
				return model.RuleResult{}, fmt.Errorf("rule %s schema evaluation failed: %w", rule.ID, err)
			}
			violated = true
			metadata = map[string]any{"jsonSchema": validation.BasicOutput()}
		}
	default:
		return model.RuleResult{}, fmt.Errorf("rule %s has unsupported kind %q", rule.ID, rule.Kind)
	}
	if !violated {
		return result, nil
	}
	pointers := make([]string, 0, len(rule.EvidencePointers)+1)
	if rule.Kind == "json-schema" {
		pointers = append(pointers, rule.TargetPointer)
	}
	pointers = append(pointers, rule.EvidencePointers...)
	pointers = uniqueStrings(pointers)
	evidence, err := evidenceRefs(traceID, envelopeID, envelopeIndex, root, pointers)
	if err != nil {
		return model.RuleResult{}, fmt.Errorf("rule %s evidence: %w", rule.ID, err)
	}
	if len(evidence) == 0 {
		return model.RuleResult{}, fmt.Errorf("rule %s produced a violation without evidence", rule.ID)
	}
	level, err := resultLevel(rule.Severity)
	if err != nil {
		return model.RuleResult{}, fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	result.Kind = "fail"
	result.Level = level
	result.Message = rule.Explanation
	result.EvidenceRefs = evidence
	result.Metadata = metadata
	return result, nil
}

func applyTrustedOutcome(result model.RuleResult, rule pack.Rule, traceID, envelopeID string, envelopeIndex int, root map[string]any, kind, messageID, message string, pointers []string, metadata map[string]any) (model.RuleResult, error) {
	result.Kind = kind
	result.MessageID = messageID
	result.Message = message
	if override := rule.Messages[messageID]; override != "" {
		result.Message = override
	}
	result.Metadata = metadata
	if kind == "fail" {
		level, err := resultLevel(rule.Severity)
		if err != nil {
			return model.RuleResult{}, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		result.Level = level
	}
	if kind == "fail" || kind == "open" {
		evidence, err := evidenceRefs(traceID, envelopeID, envelopeIndex, root, pointers)
		if err != nil {
			return model.RuleResult{}, fmt.Errorf("rule %s trusted evidence: %w", rule.ID, err)
		}
		if len(evidence) == 0 {
			return model.RuleResult{}, fmt.Errorf("rule %s trusted result %s produced no evidence", rule.ID, kind)
		}
		result.EvidenceRefs = evidence
	}
	return result, nil
}

func evidenceRefs(traceID, envelopeID string, envelopeIndex int, root map[string]any, pointers []string) ([]model.EvidenceRef, error) {
	pointers = uniqueStrings(pointers)
	evidence := make([]model.EvidenceRef, 0, len(pointers))
	for _, pointer := range pointers {
		if _, err := jsonpointer.Resolve(root, pointer); err != nil {
			return nil, fmt.Errorf("evidence pointer %q: %w", pointer, err)
		}
		canonical := pointer
		if envelopeIndex >= 0 {
			canonical = envelopePointer(envelopeIndex, pointer)
		}
		evidence = append(evidence, model.EvidenceRef{TraceID: traceID, EnvelopeID: envelopeID, JSONPointer: canonical})
	}
	return evidence, nil
}

func resultLevel(severity string) (string, error) {
	switch severity {
	case "error":
		return "error", nil
	case "warning":
		return "warning", nil
	case "info":
		return "note", nil
	default:
		return "", fmt.Errorf("unsupported rule severity %q", severity)
	}
}

func evalBool(program cel.Program, activation map[string]any) (bool, error) {
	if program == nil {
		return false, fmt.Errorf("CEL program is nil")
	}
	value, _, err := program.Eval(activation)
	if err != nil {
		return false, err
	}
	boolean, ok := value.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL returned %T (%v), expected bool", value.Value(), value.Value())
	}
	return boolean, nil
}

func envelopePointer(index int, local string) string {
	prefix := fmt.Sprintf("/envelopes/%d", index)
	if local == "" {
		return prefix
	}
	return prefix + local
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
