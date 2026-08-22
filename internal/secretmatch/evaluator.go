package secretmatch

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
)

type SecretResolver interface {
	Lookup(ref string) (value string, ok bool, err error)
}

type Outcome struct {
	Kind             string
	MessageID        string
	Message          string
	EvidencePointers []string
	Metadata         map[string]any
}

type candidateValue struct {
	value string
	proof []string
}

func Evaluate(recipe pack.SecretMatchRecipe, envelope model.Envelope, secrets SecretResolver) (Outcome, error) {
	candidate, terminal, err := resolveCandidate(recipe.Candidate, envelope)
	if err != nil || terminal != nil {
		if terminal != nil {
			return *terminal, nil
		}
		return Outcome{}, err
	}

	if secrets == nil {
		return secretUnavailable(), nil
	}
	secret, ok, err := secrets.Lookup(recipe.Secret.Ref)
	if err != nil {
		return Outcome{}, fmt.Errorf("resolve secret %q: %w", recipe.Secret.Ref, err)
	}
	if !ok {
		return secretUnavailable(), nil
	}
	if secret == "" {
		return Outcome{}, fmt.Errorf("configured secret %q is empty", recipe.Secret.Ref)
	}

	// Compare fixed-size digests so a candidate with a different length does not
	// take the immediate length-mismatch path of subtle.ConstantTimeCompare.
	candidateDigest := sha256.Sum256([]byte(candidate.value))
	secretDigest := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(candidateDigest[:], secretDigest[:]) != 1 {
		return Outcome{
			Kind:             "fail",
			MessageID:        "secret-mismatch",
			Message:          "The received shared secret does not match the configured secret.",
			EvidencePointers: candidate.proof,
		}, nil
	}

	return Outcome{
		Kind:      "pass",
		MessageID: "secret-match-valid",
		Message:   "The received shared secret matches the configured secret.",
	}, nil
}

func resolveCandidate(candidate pack.SecretMatchCandidate, envelope model.Envelope) (candidateValue, *Outcome, error) {
	sources := 0
	if candidate.FromHeader != nil {
		sources++
	}
	if candidate.FromQuery != nil {
		sources++
	}
	if candidate.FromDecodedBody != nil {
		sources++
	}
	if sources != 1 {
		return candidateValue{}, nil, fmt.Errorf("secret-match candidate must declare exactly one source, got %d", sources)
	}

	switch {
	case candidate.FromHeader != nil:
		return resolveHeader(*candidate.FromHeader, envelope)
	case candidate.FromQuery != nil:
		return resolveQuery(*candidate.FromQuery, envelope)
	case candidate.FromDecodedBody != nil:
		return resolveDecodedBody(*candidate.FromDecodedBody, envelope)
	default:
		return candidateValue{}, nil, fmt.Errorf("secret-match candidate has no source")
	}
}

func resolveHeader(source pack.SecretMatchHeaderSource, envelope model.Envelope) (candidateValue, *Outcome, error) {
	values := make([]string, 0, 2)
	indexes := make([]int, 0, 2)
	for i, header := range envelope.Request.Headers {
		if strings.EqualFold(header.Name, source.Name) {
			values = append(values, header.Value)
			indexes = append(indexes, i)
		}
	}
	if len(values) == 0 {
		proof := []string{"/request/headers", "/request/headersCompleteness"}
		if envelope.Request.HeadersCompleteness != "complete" {
			out := open("insufficient-header-evidence", "The captured header set is incomplete, so the secret-bearing header cannot be proven absent.", proof)
			return candidateValue{}, &out, nil
		}
		out := failure("missing-secret-input", "The required secret-bearing header is missing.", proof)
		return candidateValue{}, &out, nil
	}

	proof := make([]string, 0, len(indexes))
	for _, index := range indexes {
		proof = append(proof, fmt.Sprintf("/request/headers/%d/value", index))
	}
	if len(values) != 1 {
		out := failureWithCount("ambiguous-secret-input", "Multiple values were observed for a header that must carry exactly one shared secret.", proof, len(values))
		return candidateValue{}, &out, nil
	}
	return candidateValue{value: values[0], proof: proof}, nil, nil
}

func resolveQuery(source pack.SecretMatchQuerySource, envelope model.Envelope) (candidateValue, *Outcome, error) {
	proof := []string{"/request/query", "/request/queryFidelity"}
	if envelope.Request.QueryFidelity != "exact" {
		out := open("insufficient-query-evidence", "Exact decoded query evidence is unavailable, so the secret-bearing query parameter cannot be decided safely.", proof)
		return candidateValue{}, &out, nil
	}

	values := make([]string, 0, 2)
	indexes := make([]int, 0, 2)
	for i, item := range envelope.Request.Query {
		if item.Name == source.Name {
			values = append(values, item.Value)
			indexes = append(indexes, i)
		}
	}
	if len(values) == 0 {
		out := failure("missing-secret-input", "The required secret-bearing query parameter is missing.", proof)
		return candidateValue{}, &out, nil
	}
	proof = proof[:0]
	for _, index := range indexes {
		proof = append(proof, fmt.Sprintf("/request/query/%d/value", index))
	}
	if len(values) != 1 {
		out := failureWithCount("ambiguous-secret-input", "Multiple values were observed for a query parameter that must carry exactly one shared secret.", proof, len(values))
		return candidateValue{}, &out, nil
	}
	return candidateValue{value: values[0], proof: proof}, nil, nil
}

func resolveDecodedBody(source pack.SecretMatchDecodedBodySource, envelope model.Envelope) (candidateValue, *Outcome, error) {
	proof := []string{"/request/decodedBody"}
	if envelope.Request.DecodedBody == nil {
		out := open("insufficient-body-evidence", "The decoded request body is unavailable, so the secret-bearing JSON field cannot be decided safely.", proof)
		return candidateValue{}, &out, nil
	}

	current := envelope.Request.DecodedBody
	pointer := "/request/decodedBody"
	for _, key := range source.Path {
		pointer += "/" + escapeJSONPointer(key)
		object, ok := current.(map[string]any)
		if !ok {
			out := failure("malformed-secret-input", "The configured secret-match JSON path crosses a non-object value.", []string{pointer})
			return candidateValue{}, &out, nil
		}
		next, ok := object[key]
		if !ok {
			out := failure("missing-secret-input", "The required secret-bearing JSON field is missing.", []string{pointer})
			return candidateValue{}, &out, nil
		}
		current = next
	}

	value, ok := current.(string)
	if !ok {
		out := failure("malformed-secret-input", "The secret-bearing JSON field must be a string.", []string{pointer})
		return candidateValue{}, &out, nil
	}
	return candidateValue{value: value, proof: []string{pointer}}, nil, nil
}

func escapeJSONPointer(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

func failure(id, message string, proof []string) Outcome {
	return Outcome{Kind: "fail", MessageID: id, Message: message, EvidencePointers: proof}
}

func failureWithCount(id, message string, proof []string, count int) Outcome {
	out := failure(id, message, proof)
	out.Metadata = map[string]any{"candidateCount": count}
	return out
}

func open(id, message string, proof []string) Outcome {
	return Outcome{Kind: "open", MessageID: id, Message: message, EvidencePointers: proof}
}

func secretUnavailable() Outcome {
	return Outcome{
		Kind:             "open",
		MessageID:        "secret-unavailable",
		Message:          "The configured secret is unavailable, so this authentication check cannot be decided.",
		EvidencePointers: []string{"/request"},
	}
}
