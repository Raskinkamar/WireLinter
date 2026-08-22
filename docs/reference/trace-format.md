# Trace format

A Trace is the canonical evidence document consumed by `wirelint lint`. The normative schema is [`schemas/trace-v1.schema.json`](../../schemas/trace-v1.schema.json).

This page explains the fields that matter when producing or reviewing a Trace; it does not replace the schema.

## Top level

A Trace contains:

- `schemaVersion` — currently `1`;
- `traceId` — stable identity for the capture;
- `provider` — provider contract ID;
- `startedAt` and optional `endedAt` timestamps;
- `envelopes` — captured HTTP exchanges;
- `observations` — optional non-HTTP evidence associated with the scenario;
- optional `scenario` and `metadata`.

## Envelopes

An envelope records one HTTP exchange. It contains an ID, provider, capture time, request evidence and an optional response.

`direction` is optional for backward compatibility. Capture sources may set it to:

- `inbound` for provider-to-application traffic;
- `outbound` for application-to-provider traffic.

The outbound proxy sets `outbound`. Older Trace v1 fixtures and capture sources may omit the field. A contract that depends on direction should use evidence-aware `requires` semantics rather than guessing.

Optional fields such as `eventType`, `deliveryId` and `scenarioStep` let a capture source preserve useful provider/scenario identity without changing the HTTP evidence itself.

`receivedAt` is the legacy Trace v1 envelope timestamp name. Outbound acquisition uses it as the time the exchange entered WireLinter; the direction-specific observation (`request.sent`) describes the actual traffic semantics.

## Request evidence

The request records semantic HTTP fields and their fidelity:

```json
{
  "method": "POST",
  "url": "https://example.test/webhook",
  "headers": [],
  "headersCompleteness": "complete",
  "rawQuery": "",
  "queryFidelity": "exact",
  "bodyFidelity": "exact",
  "rawBodyBase64": "e30="
}
```

`decodedBody` may be included for rules that operate on semantic payload content. It is not a substitute for the raw body when a provider signs exact bytes.

This same field is used for JSON API and GraphQL semantics. WireLinter does not need a separate GraphQL transport representation to inspect a decoded GraphQL request or response.

## Redacted semantic values

A header or decoded query item may contain `"redacted": true`. The value then represents evidence deliberately sanitized by the capture source rather than the original credential.

For example:

```json
{
  "name": "Authorization",
  "value": "Bearer <redacted>",
  "redacted": true
}
```

The outbound proxy keeps enough non-secret structure to support rules such as authentication-scheme checks while preventing common credentials from being written to the Trace.

Redaction applies to the Trace representation, not to the upstream request. The provider still receives the original value.

## Fidelity fields

Fidelity is explicit so a rule can distinguish missing or altered evidence from a real violation.

### `bodyFidelity`

- `exact` — `rawBodyBase64` contains the exact captured body bytes;
- `reconstructed` — a body is available, but it was rebuilt from another representation;
- `unavailable` — raw body evidence is not available and `rawBodyBase64` is `null`.

A byte-level signature recipe can require `exact` and report `open` when only reconstructed evidence exists.

### `headersCompleteness`

- `complete` — absence of a header is meaningful evidence;
- `partial` — observed headers are usable, but an unobserved header cannot safely be treated as absent;
- `unavailable` — no semantic header evidence is available.

A redacted header can still be part of a complete semantic header collection. `redacted` describes the value, while `headersCompleteness` describes the collection.

### `queryFidelity`

- `exact` — the query component is known as captured;
- `reconstructed` — query evidence exists but was rebuilt or deliberately redacted;
- `unavailable` — query evidence is unavailable.

The outbound proxy preserves an exact non-sensitive query. If it redacts a credential-bearing query value, it marks the resulting query as reconstructed instead of falsely claiming byte fidelity.

## Raw bytes

`rawBodyBase64` is base64 in the JSON representation because a Trace must be able to represent arbitrary bytes. The runtime decodes it before trusted byte-level operations.

`bodySha256` may be present as supporting evidence but does not replace the raw body when a rule needs to reproduce a provider signature.

## Response evidence

A response records status, headers, body evidence and `durationMs`. Provider contracts can use it for inbound acknowledgement checks and outbound API-result checks.

If there is no response evidence, rules that require a response should normally remain `open` rather than manufacturing a failure.

An HTTP status is not necessarily the full application-level result. For example, a provider contract may separately inspect a decoded GraphQL response and report a non-empty `errors` member even when the transport status is successful.

## Hand-written traces

For tests, prefer existing fixtures as a starting point rather than writing a Trace from memory. The schema rejects unknown fields and the CLI uses strict JSON decoding.

See [`examples/traces/`](../../examples/traces/) and [Result semantics](results.md).
