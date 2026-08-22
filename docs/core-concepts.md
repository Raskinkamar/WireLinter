# Core concepts

WireLinter evaluates HTTP integration evidence against a provider contract. Five concepts make up that path.

## Trace

A Trace is the canonical input to the engine. It contains one or more captured envelopes with request evidence and, when available, response evidence.

An envelope may describe provider-to-application traffic (`inbound`) or application-to-provider traffic (`outbound`). Direction is evidence, not a different engine path.

The model records evidence fidelity explicitly. A reconstructed JSON body is not treated as interchangeable with exact bytes when a signature depends on those bytes, and a redacted query is not called exact.

Saved fixtures, the inbound listener and the outbound proxy all converge on the same Trace model.

## Provider contract

A provider contract is a versioned pack under `packs/`. It describes one concrete protocol surface: a delivery mode, API surface, authentication mode or setup handshake with a stable set of documented expectations.

The distinction matters. A provider name is not enough to tell you which direction, endpoint, authentication scheme, signature algorithm, response semantics or acknowledgement rules apply.

REST-like APIs and GraphQL APIs do not need different cores. Their provider-specific semantics belong in contracts over HTTP evidence.

## Rule

A rule turns provider documentation into a decision over Trace evidence. Packs may use JSON Schema, CEL or a trusted primitive depending on the job.

General policy should stay declarative. Cryptographic operations and exact secret comparisons stay in bounded trusted code so a pack does not receive secret material directly.

A rule can combine transport and application-level evidence. For example, an outbound GraphQL contract can pass an HTTP-status rule and fail a separate semantic rule because the JSON response contains GraphQL errors.

## Evidence

A rule can only fail when WireLinter has enough evidence to make that decision. Missing evidence is represented separately from a violation.

For evidence-aware CEL rules the lifecycle is:

```text
when == false      -> notApplicable
requires == false  -> open
assert == true     -> pass
assert == false    -> fail
```

This avoids turning an incomplete capture into a false success or false failure.

Evidence may also be deliberately redacted. A redacted value can prove structural facts such as the presence of a Bearer Authorization header without exposing the credential itself. Rules that require the original secret value must use a trusted mechanism or remain open.

## Report

The Report is the canonical output. It contains the provider contract, Trace identity, per-rule results and a summary.

The CLI renders a text report for humans and JSON for automation. The semantics are identical in both formats.

See [Result semantics](reference/results.md).

## Trusted primitives

The trusted runtime exists for mechanisms that should not be implemented in arbitrary pack expressions. Current protocol generations include declarative HMAC signatures, exact secret matching and bounded digest matching.

The core is provider-neutral: a primitive knows how to verify a mechanism, not which vendor asked for it.

## Acquisition paths

WireLinter currently has three ways to obtain evidence:

- load a saved canonical Trace with `lint`;
- observe provider-to-application traffic with `listen`;
- observe application-to-provider traffic with `proxy`.

Acquisition is intentionally separate from evaluation. A new capture source should produce the canonical Trace instead of adding a parallel rule engine.

## Pack Protocol

Pack Protocol versions describe what a provider pack is allowed to express. They are independent from the WireLinter product version.

- 1.0: JSON Schema and CEL
- 1.1: trusted signature recipes
- 1.2: evidence sufficiency through `requires`
- 1.3: exact secret matching
- 1.4: SHA-256 digest matching for keyed preimage contracts

The ADRs under [Architecture](architecture/README.md) contain the design rationale behind these boundaries.
