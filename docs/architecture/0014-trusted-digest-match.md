# ADR 0014: trusted digest matching

## Status

Accepted.

## Context

Some providers authenticate a webhook with a digest over a message that includes a shared secret, but do not use HMAC.

PagBank Orders/Payments is the first supported example: the provider documents an authenticity token produced from the account token, a literal separator and the exact raw payload, hashed with SHA-256 and sent as a hexadecimal header value.

Treating this as HMAC would be cryptographically incorrect. Exposing the account token to CEL so a pack could construct the preimage would also cross the existing secret-resolution boundary.

## Decision

Pack Protocol 1.4 adds a bounded trusted `digest-match` primitive.

The initial surface is intentionally narrow:

- SHA-256 only;
- UTF-8 configured secret material;
- exactly one configured secret in the message construction;
- message segments limited to the secret, literals and exact raw request body bytes;
- one candidate header encoded as hexadecimal;
- constant-time comparison;
- exact body fidelity required whenever the raw body participates in the digest.

Pack Protocol 1.3 and older packs cannot declare digest matches.

## Consequences

Provider packs can model keyed preimage digest schemes without mislabeling them as HMAC and without exposing secrets to CEL or reports.

The primitive is not a general-purpose hashing DSL. New algorithms, encodings, URL canonicalization or arbitrary field composition require a separate compatibility decision and tests before the schema is widened.

Provider-specific branches remain prohibited in the core. A provider consumes the primitive by declaring data; it does not add vendor logic to the evaluator.

## Security notes

A missing configured secret produces insufficient-evidence behavior rather than a guessed result. Raw request bytes are used only when their fidelity is known to be exact. Digest candidates are compared in trusted code.
