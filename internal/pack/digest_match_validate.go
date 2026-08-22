package pack

import "fmt"

func validateDigestMatchRecipe(recipe DigestMatchRecipe) error {
	if recipe.Secret.Representation != "utf8" {
		return fmt.Errorf("digest match %q has unsupported secret representation %q", recipe.ID, recipe.Secret.Representation)
	}
	if recipe.Candidate.Encoding != "hex" {
		return fmt.Errorf("digest match %q has unsupported candidate encoding %q", recipe.ID, recipe.Candidate.Encoding)
	}
	if recipe.Candidate.FromHeader.Cardinality != "exactly-one" {
		return fmt.Errorf("digest match %q candidate header cardinality must be exactly-one", recipe.ID)
	}
	if recipe.Hash.Algorithm != "sha256" {
		return fmt.Errorf("digest match %q has unsupported hash algorithm %q", recipe.ID, recipe.Hash.Algorithm)
	}
	if recipe.Comparison != "constant-time-exact" {
		return fmt.Errorf("digest match %q has unsupported comparison %q", recipe.ID, recipe.Comparison)
	}
	secretSegments := 0
	rawBodySegments := 0
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
			rawBodySegments++
			sources++
			if segment.FromRawBody.RequireFidelity != "exact" {
				return fmt.Errorf("digest match %q message segment %d requires unsupported body fidelity %q", recipe.ID, i, segment.FromRawBody.RequireFidelity)
			}
		}
		if sources != 1 {
			return fmt.Errorf("digest match %q message segment %d must declare exactly one source", recipe.ID, i)
		}
	}
	if secretSegments != 1 {
		return fmt.Errorf("digest match %q must use the configured secret exactly once, got %d segments", recipe.ID, secretSegments)
	}
	if rawBodySegments > 1 {
		return fmt.Errorf("digest match %q may use the raw body at most once, got %d segments", recipe.ID, rawBodySegments)
	}
	return nil
}
