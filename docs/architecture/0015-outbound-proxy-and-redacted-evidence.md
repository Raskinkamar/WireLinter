# ADR 0015: Outbound proxy acquisition and redacted evidence

## Status

Accepted.

## Context

The original live acquisition path was intentionally inbound: a provider sends a webhook or callback to WireLinter, which forwards the delivery to a fixed local application endpoint. That shape is not equivalent to application-to-provider API traffic.

Outbound integrations need the inverse flow. The application chooses a path and query, sends credentials to a remote provider and consumes the provider response. GraphQL adds useful semantic checks, but it still rides on the same HTTP request/response evidence model.

Reusing the inbound listener for both directions would make target path semantics, trust boundaries and diagnostics ambiguous.

## Decision

WireLinter has a separate outbound acquisition component and CLI command, `proxy`.

The proxy:

- binds to loopback by default;
- forwards an application's request to one configured HTTP(S) provider base URL;
- joins the local request path with the configured target path and preserves the request query upstream;
- does not follow upstream redirects;
- bounds request and response capture sizes;
- produces the existing canonical Trace rather than a GraphQL- or REST-specific trace type;
- marks the envelope `direction` as `outbound`;
- records decoded JSON only as additional semantic evidence; exact body bytes remain authoritative where byte fidelity matters.

Provider policy remains declarative. A GraphQL contract may inspect `request.decodedBody` and `response.decodedBody`, but the proxy does not know GitHub, Shopify, Meta or GraphQL rule semantics.

## Credential evidence

The upstream request receives the application's original headers and query values. Evidence is a separate representation.

Before an outbound Trace is evaluated or persisted, common credential-bearing semantic headers and query parameters are redacted. The Trace marks redacted entries explicitly. Authorization keeps its authentication scheme, for example `Bearer <redacted>`, so rules can diagnose the mechanism without obtaining the credential.

Redacting a query value changes `queryFidelity` to `reconstructed`; WireLinter must not describe deliberately altered query evidence as exact.

Body payloads are not generically redacted. Bodies are provider-shaped and may contain values that cannot be safely identified without changing semantics. Trace persistence therefore remains opt-in and traces remain sensitive artifacts.

## Consequences

REST-style APIs, GraphQL APIs, Meta Graph API and other HTTP integration surfaces can use the same acquisition path. Their differences live in provider contracts.

The v1 Trace field `receivedAt` remains for schema compatibility even for outbound envelopes; `direction` and observations (`request.sent`, `response.received`) carry the traffic semantics. A future Trace major version may rename timestamps if the public model is revised more broadly.

The listener and proxy share some HTTP mechanics but remain separate components because their trust and routing semantics differ. Shared implementation should only be extracted when it can preserve those distinctions explicitly.
