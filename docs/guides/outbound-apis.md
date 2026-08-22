# Debugging outbound APIs

`wirelint proxy` observes HTTP calls made by a local application to a third-party API. It forwards the request to a fixed upstream provider, returns the provider response to the application and evaluates the captured exchange with the selected provider contract.

Use `proxy` for application-to-provider traffic. Use [`listen`](live-webhooks.md) for provider-to-application deliveries such as webhooks and callbacks.

## GitHub GraphQL example

Start WireLinter with the GitHub GraphQL contract:

```bash
wirelint proxy \
  --provider github-graphql-api \
  --target https://api.github.com
```

The proxy listens on `127.0.0.1:4546` by default. While debugging, point the application's GitHub GraphQL base URL at:

```text
http://127.0.0.1:4546/graphql
```

A request made to that local URL is forwarded to `https://api.github.com/graphql`. Request paths and query strings are preserved relative to `--target`, so the same mechanism works for ordinary HTTP APIs as well as GraphQL endpoints.

WireLinter prints a report after the provider response is returned. Trace persistence is off unless `--save-dir` is set.

## GraphQL is evaluated as HTTP plus application semantics

The proxy does not add a second GraphQL transport model. The canonical Trace already records the HTTP request, response, exact body bytes when captured, and decoded JSON when available.

A GraphQL provider contract can therefore check both layers independently. For example, an HTTP `200` can pass the transport rule while a non-empty GraphQL `errors` member fails a semantic rule. Provider-specific GraphQL expectations remain in the pack rather than in the Go proxy.

The first bundled outbound contract is `github-graphql-api`. It is a proof of the acquisition path, not a special case in the core.

## Target mapping

`--target` is a base URL. The local request path is appended to its path:

```text
--target https://api.example.com
local    http://127.0.0.1:4546/v1/orders
upstream https://api.example.com/v1/orders
```

A target may itself contain a path:

```text
--target https://api.example.com/platform
local    http://127.0.0.1:4546/graphql
upstream https://api.example.com/platform/graphql
```

The target must use HTTP or HTTPS and cannot contain userinfo, a fragment or a query string. Put request-specific query parameters on the local request instead.

## Credential handling

Outbound requests commonly contain application credentials. WireLinter forwards the original request to the upstream provider, but Trace evidence redacts common credential-bearing headers and query parameters before the exchange is evaluated or optionally persisted.

For example, an Authorization value is represented as:

```json
{
  "name": "Authorization",
  "value": "Bearer <redacted>",
  "redacted": true
}
```

Preserving the scheme lets a provider contract distinguish Bearer authentication from another mechanism without receiving the credential itself.

When a query value is redacted, `queryFidelity` becomes `reconstructed`: the saved query is deliberately no longer the exact bytes sent upstream. Non-sensitive query strings remain exact.

This redaction is intentionally limited to semantic headers and query parameters. Request and response bodies can still contain credentials, personal data or business data. Trace persistence is opt-in, and saved traces should still be treated as sensitive artifacts. See [`SECURITY.md`](../../SECURITY.md).

## Redirects and local exposure

The outbound client does not follow provider redirects automatically. The returned redirect remains part of the observed exchange and is returned to the application.

The local proxy binds to loopback by default. `--allow-public-listen` is an explicit opt-in because exposing a development proxy can expose application traffic and credentials to other hosts.

## Saved traces

To retain exchanges for later linting:

```bash
wirelint proxy \
  --provider github-graphql-api \
  --target https://api.github.com \
  --save-dir ./traces
```

Saved files use the same Trace schema consumed by `wirelint lint`, so a live outbound exchange can be reproduced without a different analysis path.
