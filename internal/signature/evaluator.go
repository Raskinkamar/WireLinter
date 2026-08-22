package signature

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
)

const (
	maxParserInputBytes = 64 << 10
	maxParsedFields     = 128
	maxBindingValues    = 64
	maxCandidates       = 32
)

// SecretResolver deliberately abstracts secret acquisition away from provider
// packs and the engine. The CLI may later implement this with environment
// variables, keychains, CI secret stores, or an explicit in-memory map.
type SecretResolver interface {
	Lookup(ref string) (value string, ok bool, err error)
}

type MapSecrets map[string]string

func (m MapSecrets) Lookup(ref string) (string, bool, error) {
	value, ok := m[ref]
	return value, ok, nil
}

// Outcome is provider-neutral. MessageID is stable automation surface; Message
// is a safe default that provider rules may override without changing runtime
// semantics.
type Outcome struct {
	Kind             string
	MessageID        string
	Message          string
	EvidencePointers []string
	Metadata         map[string]any
}

type valueKind uint8

const (
	kindAbsent valueKind = iota
	kindString
	kindBytes
	kindStrings
)

type bindingValue struct {
	kind     valueKind
	text     string
	bytes    []byte
	texts    []string
	evidence []string
}

type pair struct {
	key   string
	value string
}

type evaluator struct {
	recipe      pack.SignatureRecipe
	envelope    model.Envelope
	secrets     SecretResolver
	bindings    map[string]bindingValue
	parsers     map[string][]pair
	parserProof map[string][]string
}

func Evaluate(recipe pack.SignatureRecipe, envelope model.Envelope, secrets SecretResolver) (Outcome, error) {
	e := &evaluator{
		recipe:      recipe,
		envelope:    envelope,
		secrets:     secrets,
		bindings:    map[string]bindingValue{},
		parsers:     map[string][]pair{},
		parserProof: map[string][]string{},
	}
	return e.evaluate()
}

func (e *evaluator) evaluate() (Outcome, error) {
	candidateValue, terminal, err := e.resolveBinding(e.recipe.Candidates.Binding, true)
	if err != nil || terminal != nil {
		return derefOutcome(terminal), err
	}
	candidateTexts, err := candidateStrings(candidateValue)
	if err != nil {
		return Outcome{}, err
	}
	if len(candidateTexts) > maxCandidates {
		return failure("malformed-signature", "Too many signature candidates were observed.", candidateValue.evidence), nil
	}

	decodedCandidates := make([][]byte, 0, len(candidateTexts))
	malformedCandidates := 0
	for _, candidate := range candidateTexts {
		decoded, ok := decodeCandidate(candidate, e.recipe.Candidates)
		if !ok {
			malformedCandidates++
			continue
		}
		decodedCandidates = append(decodedCandidates, decoded)
	}
	if len(decodedCandidates) == 0 {
		return Outcome{
			Kind:             "fail",
			MessageID:        "malformed-signature",
			Message:          defaultMessage("malformed-signature"),
			EvidencePointers: candidateValue.evidence,
			Metadata:         map[string]any{"malformedCandidates": malformedCandidates},
		}, nil
	}

	segments := make([]bindingValue, 0, len(e.recipe.Message))
	for _, segment := range e.recipe.Message {
		if segment.Literal != nil {
			segments = append(segments, bindingValue{kind: kindBytes, bytes: []byte(*segment.Literal)})
			continue
		}
		value, terminal, err := e.resolveBinding(segment.Binding, false)
		if err != nil || terminal != nil {
			return derefOutcome(terminal), err
		}
		if value.kind == kindAbsent && segment.OmitIfAbsent {
			continue
		}
		if value.kind == kindAbsent {
			return Outcome{}, fmt.Errorf("signature %s required message binding %q resolved absent", e.recipe.ID, segment.Binding)
		}
		if value.kind == kindStrings {
			return Outcome{}, fmt.Errorf("signature %s message binding %q unexpectedly resolved to a list", e.recipe.ID, segment.Binding)
		}
		if segment.Prefix != "" {
			segments = append(segments, bindingValue{kind: kindBytes, bytes: []byte(segment.Prefix)})
		}
		segments = append(segments, value)
		if segment.Suffix != "" {
			segments = append(segments, bindingValue{kind: kindBytes, bytes: []byte(segment.Suffix)})
		}
	}

	secret, terminal, err := e.resolveSecret()
	if err != nil || terminal != nil {
		return derefOutcome(terminal), err
	}

	mac, err := newMAC(e.recipe.MAC.Algorithm, secret)
	if err != nil {
		return Outcome{}, fmt.Errorf("signature %s: %w", e.recipe.ID, err)
	}
	for _, segment := range segments {
		switch segment.kind {
		case kindString:
			_, _ = mac.Write([]byte(segment.text))
		case kindBytes:
			_, _ = mac.Write(segment.bytes)
		default:
			return Outcome{}, fmt.Errorf("signature %s message contains unsupported value kind %d", e.recipe.ID, segment.kind)
		}
	}
	expected := mac.Sum(nil)

	matched := false
	for _, candidate := range decodedCandidates {
		if hmac.Equal(expected, candidate) {
			matched = true
		}
	}
	if !matched {
		return Outcome{
			Kind:             "fail",
			MessageID:        "signature-mismatch",
			Message:          defaultMessage("signature-mismatch"),
			EvidencePointers: uniquePointers(candidateValue.evidence, messageEvidence(segments)),
			Metadata:         map[string]any{"candidateCount": len(candidateTexts), "malformedCandidates": malformedCandidates},
		}, nil
	}

	if e.recipe.Freshness != nil {
		timestampValue, terminal, err := e.resolveBinding(e.recipe.Freshness.TimestampBinding, false)
		if err != nil || terminal != nil {
			return derefOutcome(terminal), err
		}
		if timestampValue.kind != kindString {
			return Outcome{}, fmt.Errorf("signature %s freshness timestamp did not resolve to string", e.recipe.ID)
		}
		timestamp, parseErr := strconv.ParseInt(strings.TrimSpace(timestampValue.text), 10, 64)
		if parseErr != nil {
			return failure("malformed-signature", "Signature timestamp is not a valid Unix timestamp.", timestampValue.evidence), nil
		}
		age := e.envelope.ReceivedAt.Unix() - timestamp
		if maxAge := e.recipe.Freshness.MaxAgeSeconds; maxAge != nil && age > int64(*maxAge) {
			return failure("timestamp-stale", defaultMessage("timestamp-stale"), timestampValue.evidence), nil
		}
		if maxFuture := e.recipe.Freshness.MaxFutureSeconds; maxFuture != nil && age < -int64(*maxFuture) {
			return failure("timestamp-future", defaultMessage("timestamp-future"), timestampValue.evidence), nil
		}
	}

	return Outcome{
		Kind:      "pass",
		MessageID: "signature-valid",
		Message:   defaultMessage("signature-valid"),
		Metadata:  map[string]any{"candidateCount": len(candidateTexts), "malformedCandidates": malformedCandidates},
	}, nil
}

func (e *evaluator) resolveSecret() ([]byte, *Outcome, error) {
	if e.secrets == nil {
		out := open("secret-unavailable", defaultMessage("secret-unavailable"), []string{"/request"})
		return nil, &out, nil
	}
	raw, ok, err := e.secrets.Lookup(e.recipe.Secret.Ref)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve secret %q: %w", e.recipe.Secret.Ref, err)
	}
	if !ok {
		out := open("secret-unavailable", defaultMessage("secret-unavailable"), []string{"/request"})
		return nil, &out, nil
	}
	if raw == "" {
		return nil, nil, fmt.Errorf("configured secret %q is empty", e.recipe.Secret.Ref)
	}

	switch e.recipe.Secret.Representation {
	case "utf8":
		return []byte(raw), nil, nil
	case "prefixed-base64":
		if !strings.HasPrefix(raw, e.recipe.Secret.Prefix) {
			return nil, nil, fmt.Errorf("configured secret %q does not have required prefix", e.recipe.Secret.Ref)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, e.recipe.Secret.Prefix))
		if err != nil {
			return nil, nil, fmt.Errorf("configured secret %q has invalid base64 payload", e.recipe.Secret.Ref)
		}
		if len(decoded) == 0 {
			return nil, nil, fmt.Errorf("configured secret %q decodes to empty key material", e.recipe.Secret.Ref)
		}
		return decoded, nil, nil
	default:
		return nil, nil, fmt.Errorf("signature %s has unsupported secret representation %q", e.recipe.ID, e.recipe.Secret.Representation)
	}
}

func (e *evaluator) resolveBinding(name string, candidateRole bool) (bindingValue, *Outcome, error) {
	if cached, ok := e.bindings[name]; ok {
		return cached, nil, nil
	}
	binding, ok := e.recipe.Bindings[name]
	if !ok {
		return bindingValue{}, nil, fmt.Errorf("signature %s references unknown binding %q", e.recipe.ID, name)
	}

	var value bindingValue
	var terminal *Outcome
	var err error
	switch {
	case binding.FromRawBody != nil:
		value, terminal = e.fromRawBody()
	case binding.FromHeader != nil:
		value, terminal = e.fromHeader(*binding.FromHeader, candidateRole)
	case binding.FromQuery != nil:
		value, terminal = e.fromQuery(*binding.FromQuery)
	case binding.FromField != nil:
		value, terminal, err = e.fromField(*binding.FromField, candidateRole)
	default:
		err = fmt.Errorf("signature %s binding %q has no source", e.recipe.ID, name)
	}
	if err != nil || terminal != nil {
		return bindingValue{}, terminal, err
	}
	e.bindings[name] = value
	return value, nil, nil
}

func (e *evaluator) fromRawBody() (bindingValue, *Outcome) {
	req := e.envelope.Request
	proof := []string{"/request/bodyFidelity", "/request/rawBodyBase64"}
	if req.BodyFidelity != "exact" {
		out := open("insufficient-body-fidelity", defaultMessage("insufficient-body-fidelity"), proof)
		return bindingValue{}, &out
	}
	return bindingValue{kind: kindBytes, bytes: req.RawBodyBase64, evidence: proof}, nil
}

func (e *evaluator) fromHeader(source pack.SignatureHeaderSource, candidateRole bool) (bindingValue, *Outcome) {
	values, indexes := matchingHeaders(e.envelope.Request.Headers, source.Name)
	proof := headerPointers(indexes)
	if len(values) == 0 {
		if e.envelope.Request.HeadersCompleteness != "complete" {
			out := open("insufficient-header-evidence", defaultMessage("insufficient-header-evidence"), []string{"/request/headers", "/request/headersCompleteness"})
			return bindingValue{}, &out
		}
		if source.Cardinality == "zero-or-one" {
			return bindingValue{kind: kindAbsent, evidence: []string{"/request/headers", "/request/headersCompleteness"}}, nil
		}
		id := "missing-signature-input"
		if candidateRole {
			id = "missing-signature"
		}
		out := failure(id, defaultMessage(id), []string{"/request/headers", "/request/headersCompleteness"})
		return bindingValue{}, &out
	}
	return applyCardinality(values, proof, source.Cardinality, source.TrimSpace)
}

func (e *evaluator) fromQuery(source pack.SignatureQuerySource) (bindingValue, *Outcome) {
	req := e.envelope.Request
	if req.QueryFidelity == "unavailable" || (req.Query == nil && req.RawQuery != "") {
		out := open("insufficient-query-evidence", defaultMessage("insufficient-query-evidence"), []string{"/request/rawQuery", "/request/queryFidelity"})
		return bindingValue{}, &out
	}
	values := make([]string, 0, 2)
	indexes := make([]int, 0, 2)
	for i, item := range req.Query {
		if item.Name == source.Name {
			values = append(values, item.Value)
			indexes = append(indexes, i)
		}
	}
	proof := queryPointers(indexes)
	if len(values) == 0 {
		proof = []string{"/request/query", "/request/queryFidelity"}
		if source.Cardinality == "zero-or-one" {
			return bindingValue{kind: kindAbsent, evidence: proof}, nil
		}
		out := failure("missing-signature-input", defaultMessage("missing-signature-input"), proof)
		return bindingValue{}, &out
	}
	return applyCardinality(values, proof, source.Cardinality, source.TrimSpace)
}

func (e *evaluator) fromField(source pack.SignatureFieldSource, candidateRole bool) (bindingValue, *Outcome, error) {
	pairs, proof, terminal, err := e.parse(source.Parser, candidateRole)
	if err != nil || terminal != nil {
		return bindingValue{}, terminal, err
	}
	values := make([]string, 0, 2)
	for _, item := range pairs {
		if item.key == source.Key {
			values = append(values, item.value)
		}
	}
	if len(values) == 0 {
		if source.Cardinality == "zero-or-one" {
			return bindingValue{kind: kindAbsent, evidence: proof}, nil, nil
		}
		// The signature carrier was observed and parsed, so a missing field is
		// a missing input, not a missing signature. candidateRole only affects
		// absence of the carrier itself inside parse().
		out := failure("missing-signature-input", defaultMessage("missing-signature-input"), proof)
		return bindingValue{}, &out, nil
	}
	value, terminal := applyCardinality(values, proof, source.Cardinality, false)
	return value, terminal, nil
}

func (e *evaluator) parse(name string, candidateRole bool) ([]pair, []string, *Outcome, error) {
	if cached, ok := e.parsers[name]; ok {
		return cached, e.parserProof[name], nil, nil
	}
	parser, ok := e.recipe.Parsers[name]
	if !ok {
		return nil, nil, nil, fmt.Errorf("signature %s references unknown parser %q", e.recipe.ID, name)
	}
	values, indexes := matchingHeaders(e.envelope.Request.Headers, parser.SourceHeader.Name)
	proof := headerPointers(indexes)
	if len(values) == 0 {
		if e.envelope.Request.HeadersCompleteness != "complete" {
			out := open("insufficient-header-evidence", defaultMessage("insufficient-header-evidence"), []string{"/request/headers", "/request/headersCompleteness"})
			return nil, nil, &out, nil
		}
		id := "missing-signature-input"
		if candidateRole {
			id = "missing-signature"
		}
		out := failure(id, defaultMessage(id), []string{"/request/headers", "/request/headersCompleteness"})
		return nil, nil, &out, nil
	}
	if len(values) != 1 {
		out := failure("ambiguous-signature-input", defaultMessage("ambiguous-signature-input"), proof)
		return nil, nil, &out, nil
	}
	raw := values[0]
	if parser.SourceHeader.TrimSpace {
		raw = strings.TrimSpace(raw)
	}
	if len(raw) > maxParserInputBytes {
		out := failure("malformed-signature", "Signature metadata exceeds the parser safety limit.", proof)
		return nil, nil, &out, nil
	}
	items := strings.Split(raw, parser.Format.ItemDelimiter)
	if len(items) > maxParsedFields {
		out := failure("malformed-signature", "Signature metadata contains too many fields.", proof)
		return nil, nil, &out, nil
	}
	parsed := make([]pair, 0, len(items))
	for _, item := range items {
		if parser.Format.TrimSpace {
			item = strings.TrimSpace(item)
		}
		if strings.Count(item, parser.Format.PairDelimiter) != 1 {
			out := failure("malformed-signature", defaultMessage("malformed-signature"), proof)
			return nil, nil, &out, nil
		}
		key, value, _ := strings.Cut(item, parser.Format.PairDelimiter)
		if parser.Format.TrimSpace {
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		}
		if key == "" || value == "" {
			out := failure("malformed-signature", defaultMessage("malformed-signature"), proof)
			return nil, nil, &out, nil
		}
		parsed = append(parsed, pair{key: key, value: value})
	}
	e.parsers[name] = parsed
	e.parserProof[name] = proof
	return parsed, proof, nil, nil
}

func applyCardinality(values, proof []string, cardinality string, trim bool) (bindingValue, *Outcome) {
	if len(values) > maxBindingValues {
		out := failure("ambiguous-signature-input", "Too many values were observed for one signature input.", proof)
		return bindingValue{}, &out
	}
	if trim {
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
	}
	switch cardinality {
	case "exactly-one", "zero-or-one":
		if len(values) != 1 {
			out := failure("ambiguous-signature-input", defaultMessage("ambiguous-signature-input"), proof)
			return bindingValue{}, &out
		}
		return bindingValue{kind: kindString, text: values[0], evidence: proof}, nil
	case "one-or-more":
		if len(values) == 0 {
			out := failure("missing-signature-input", defaultMessage("missing-signature-input"), proof)
			return bindingValue{}, &out
		}
		return bindingValue{kind: kindStrings, texts: values, evidence: proof}, nil
	default:
		out := failure("malformed-signature", "Signature recipe used an unsupported cardinality.", proof)
		return bindingValue{}, &out
	}
}

func candidateStrings(value bindingValue) ([]string, error) {
	switch value.kind {
	case kindString:
		return []string{value.text}, nil
	case kindStrings:
		return value.texts, nil
	default:
		return nil, fmt.Errorf("signature candidate binding resolved to unsupported kind %d", value.kind)
	}
}

func decodeCandidate(candidate string, spec pack.SignatureCandidates) ([]byte, bool) {
	if spec.StripPrefix != "" {
		if !strings.HasPrefix(candidate, spec.StripPrefix) {
			return nil, false
		}
		candidate = strings.TrimPrefix(candidate, spec.StripPrefix)
	}
	var decoded []byte
	var err error
	switch spec.Encoding {
	case "hex":
		decoded, err = hex.DecodeString(candidate)
	case "base64-standard":
		decoded, err = base64.StdEncoding.DecodeString(candidate)
	default:
		return nil, false
	}
	return decoded, err == nil && len(decoded) > 0
}

func matchingHeaders(headers []model.Header, name string) ([]string, []int) {
	values := make([]string, 0, 2)
	indexes := make([]int, 0, 2)
	for i, header := range headers {
		if strings.EqualFold(header.Name, name) {
			values = append(values, header.Value)
			indexes = append(indexes, i)
		}
	}
	return values, indexes
}

func headerPointers(indexes []int) []string {
	if len(indexes) == 0 {
		return []string{"/request/headers"}
	}
	out := make([]string, 0, len(indexes))
	for _, index := range indexes {
		out = append(out, fmt.Sprintf("/request/headers/%d/value", index))
	}
	return out
}

func queryPointers(indexes []int) []string {
	if len(indexes) == 0 {
		return []string{"/request/query"}
	}
	out := make([]string, 0, len(indexes))
	for _, index := range indexes {
		out = append(out, fmt.Sprintf("/request/query/%d/value", index))
	}
	return out
}

func messageEvidence(segments []bindingValue) []string {
	var out []string
	for _, segment := range segments {
		out = append(out, segment.evidence...)
	}
	return out
}

func uniquePointers(groups ...[]string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, group := range groups {
		for _, pointer := range group {
			if _, ok := seen[pointer]; ok {
				continue
			}
			seen[pointer] = struct{}{}
			out = append(out, pointer)
		}
	}
	return out
}

func failure(id, message string, evidence []string) Outcome {
	return Outcome{Kind: "fail", MessageID: id, Message: message, EvidencePointers: uniquePointers(evidence)}
}

func open(id, message string, evidence []string) Outcome {
	return Outcome{Kind: "open", MessageID: id, Message: message, EvidencePointers: uniquePointers(evidence)}
}

func derefOutcome(out *Outcome) Outcome {
	if out == nil {
		return Outcome{}
	}
	return *out
}

func defaultMessage(id string) string {
	switch id {
	case "signature-valid":
		return "Signature verified successfully."
	case "missing-signature":
		return "The required webhook signature is missing."
	case "malformed-signature":
		return "The webhook signature metadata is malformed."
	case "missing-signature-input":
		return "A required input used to build the provider signature is missing."
	case "ambiguous-signature-input":
		return "A signature input that must be singular was observed more than once."
	case "signature-mismatch":
		return "The computed signature does not match any valid candidate from the delivery."
	case "timestamp-stale":
		return "The signature timestamp is older than the provider's accepted window."
	case "timestamp-future":
		return "The signature timestamp is too far in the future for the provider's accepted window."
	case "secret-unavailable":
		return "The signing secret was not supplied, so authenticity cannot be decided."
	case "insufficient-body-fidelity":
		return "Exact request body bytes were not captured, so this signature cannot be verified reliably."
	case "insufficient-header-evidence":
		return "The captured header set is incomplete, so the required header cannot be proven absent."
	case "insufficient-query-evidence":
		return "The captured query evidence is insufficient to reconstruct the provider's signed inputs."
	default:
		return "Signature evaluation produced an unspecified result."
	}
}
