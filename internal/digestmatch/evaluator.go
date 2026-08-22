package digestmatch

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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

func Evaluate(recipe pack.DigestMatchRecipe, envelope model.Envelope, secrets SecretResolver) (Outcome, error) {
	if recipe.Secret.Representation != "utf8" || recipe.Candidate.Encoding != "hex" || recipe.Hash.Algorithm != "sha256" || recipe.Comparison != "constant-time-exact" {
		return Outcome{}, fmt.Errorf("digest %s uses an unsupported trusted digest configuration", recipe.ID)
	}

	source := recipe.Candidate.FromHeader
	if source.Cardinality != "exactly-one" {
		return Outcome{}, fmt.Errorf("digest %s candidate header cardinality must be exactly-one", recipe.ID)
	}
	values := make([]string, 0, 2)
	indexes := make([]int, 0, 2)
	for i, header := range envelope.Request.Headers {
		if strings.EqualFold(header.Name, source.Name) {
			value := header.Value
			if source.TrimSpace {
				value = strings.TrimSpace(value)
			}
			values = append(values, value)
			indexes = append(indexes, i)
		}
	}
	if len(values) == 0 {
		proof := []string{"/request/headers", "/request/headersCompleteness"}
		if envelope.Request.HeadersCompleteness != "complete" {
			return Outcome{Kind: "open", MessageID: "insufficient-header-evidence", Message: "The captured header set is incomplete, so the digest header cannot be proven absent.", EvidencePointers: proof}, nil
		}
		return Outcome{Kind: "fail", MessageID: "missing-digest", Message: "The required digest header is missing.", EvidencePointers: proof}, nil
	}
	proof := make([]string, 0, len(indexes)+2)
	for _, index := range indexes {
		proof = append(proof, fmt.Sprintf("/request/headers/%d/value", index))
	}
	if len(values) != 1 {
		return Outcome{Kind: "fail", MessageID: "ambiguous-digest-input", Message: "Multiple digest header values were observed where exactly one is required.", EvidencePointers: proof, Metadata: map[string]any{"candidateCount": len(values)}}, nil
	}
	candidate, err := hex.DecodeString(values[0])
	if err != nil || len(candidate) != sha256.Size {
		return Outcome{Kind: "fail", MessageID: "malformed-digest", Message: "The received digest is not a 32-byte SHA-256 value encoded as hexadecimal.", EvidencePointers: proof}, nil
	}

	secretSegments := 0
	usesBody := false
	for i, segment := range recipe.Message {
		sources := 0
		if segment.Secret {
			secretSegments++
			sources++
		}
		if segment.Literal != nil {
			sources++
		}
		if segment.FromRawBody != nil {
			usesBody = true
			sources++
			if segment.FromRawBody.RequireFidelity != "exact" {
				return Outcome{}, fmt.Errorf("digest %s message segment %d uses unsupported body fidelity", recipe.ID, i)
			}
			if envelope.Request.BodyFidelity != "exact" {
				return Outcome{Kind: "open", MessageID: "insufficient-body-fidelity", Message: "The digest uses the exact request body, but exact raw bytes are unavailable.", EvidencePointers: []string{"/request/bodyFidelity", "/request/rawBodyBase64"}}, nil
			}
		}
		if sources != 1 {
			return Outcome{}, fmt.Errorf("digest %s message segment %d must declare exactly one source", recipe.ID, i)
		}
	}
	if secretSegments != 1 {
		return Outcome{}, fmt.Errorf("digest %s must use its configured secret exactly once", recipe.ID)
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

	hasher := sha256.New()
	for _, segment := range recipe.Message {
		switch {
		case segment.Secret:
			_, _ = hasher.Write([]byte(secret))
		case segment.Literal != nil:
			_, _ = hasher.Write([]byte(*segment.Literal))
		case segment.FromRawBody != nil:
			_, _ = hasher.Write(envelope.Request.RawBodyBase64)
		}
	}
	expected := hasher.Sum(nil)
	if subtle.ConstantTimeCompare(expected, candidate) != 1 {
		if usesBody {
			proof = append(proof, "/request/bodyFidelity", "/request/rawBodyBase64")
		}
		return Outcome{Kind: "fail", MessageID: "digest-mismatch", Message: "The received digest does not match the declared SHA-256 message construction.", EvidencePointers: unique(proof)}, nil
	}
	return Outcome{Kind: "pass", MessageID: "digest-match-valid", Message: "The received digest matches the declared SHA-256 message construction."}, nil
}

func secretUnavailable() Outcome {
	return Outcome{Kind: "open", MessageID: "secret-unavailable", Message: "The configured secret is unavailable, so this digest check cannot be decided.", EvidencePointers: []string{"/request"}}
}

func unique(values []string) []string {
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
