# ADR 0013 — Trusted secret-match primitive

## Status

Accepted.

## Context

Not every authenticated integration uses a message authentication code. Some providers deliver a configured shared secret directly in a request header and require the receiver to compare that value with local configuration.

Treating that pattern as an HMAC signature would make the protocol model inaccurate. Exposing the configured secret to CEL would also cross an important trust boundary: community rules should never receive secret material.

Asaas Webhooks is the first official contract requiring this mechanism. Current Asaas configurations use an `authToken` delivered in the `asaas-access-token` header.

## Decision

Pack Protocol **1.3** adds a trusted `secret-match` rule mechanism.

The version is the **pack protocol version**, not the WireLinter product version. Normal project development remains on the initial product version until the maintainer explicitly decides otherwise.

A secret-match recipe declares only:

- a logical secret reference;
- one evidence source, initially an exactly-one HTTP header;
- exact comparison semantics;
- documentation source references.

Example:

```yaml
schemaVersion: 1
id: auth-token
sourceRefs:
  - webhook-auth-token
secret:
  ref: webhook-token
  representation: utf8
candidate:
  fromHeader:
    name: asaas-access-token
    cardinality: exactly-one
comparison: constant-time-exact
```

The provider pack does not receive the secret value. The CLI resolves the logical reference and injects it through the engine's `SecretResolver` boundary.

## Comparison behavior

The runtime:

1. locates the semantic header case-insensitively;
2. requires exactly one value;
3. does not trim or normalize the candidate;
4. resolves the configured secret outside the pack;
5. hashes candidate and secret independently with SHA-256;
6. compares the fixed-size digests with `crypto/subtle.ConstantTimeCompare`.

Hashing before the constant-time comparison ensures that candidate and expected values have equal-length comparison inputs even when the original strings differ in length.

No secret, candidate, or digest is added to Report metadata.

## Evidence semantics

The trusted primitive follows the same result model as other rules:

```text
exact match                              -> pass / secret-match-valid
configured secret unavailable            -> open / secret-unavailable
header absent + complete capture          -> fail / missing-secret-input
header absent + partial capture           -> open / insufficient-header-evidence
multiple candidate header values          -> fail / ambiguous-secret-input
candidate differs from configured secret  -> fail / secret-mismatch
```

The presence of a candidate header is useful evidence even when the wider header collection is partial. Absence is only provable when `headersCompleteness == complete`.

## Protocol compatibility

- Pack Protocol 1.0–1.2 cannot declare `secretMatches` or `secret-match` rules.
- Pack Protocol 1.3 inherits the CEL environment and evidence semantics of 1.2 and adds this trusted primitive.
- Signature recipes remain available in 1.3.

## Security boundary

`secret-match` deliberately does **not** provide:

- arbitrary string transformations;
- CEL access to secrets;
- prefix/suffix templating;
- regex comparison;
- filesystem or network secret lookup from packs;
- provider-specific Go callbacks.

If a future provider requires a materially different authentication mechanism, that mechanism should be researched and modeled explicitly instead of making `secret-match` an unconstrained transformation language.

## Consequences

- Static shared-secret webhook authentication can be modeled accurately without mislabeling it as a signature.
- Provider packs remain declarative and cannot exfiltrate local secret material.
- The same mechanism can support future providers that use an exact shared-secret header without adding provider branches to the core.
