# ADR 0009 — Local listener and forwarding boundary

Status: **Accepted for implementation**

## Context

WireLinter needs a low-friction way to acquire real integration evidence. Requiring a developer to hand-author a canonical Trace is useful for CI fixtures but is not a good primary workflow.

The first acquisition primitive should be passive. An active probe can create side effects in payment, order, messaging, CRM, or commerce systems. A local listener can observe a delivery the developer already chose to trigger and forward it to the application under test.

Stripe documents `stripe listen --forward-to ...` as its normal local-webhook development flow and issues a listener-specific signing secret for signature verification. Other providers can reach a local WireLinter listener through their own CLI, a developer-owned tunnel, or another forwarding mechanism. WireLinter does not need to become a tunnel provider.

Go's HTTP stack is semantic rather than wire-lossless. `net/http` canonicalizes header names, promotes `Host` out of the Header map, and represents transfer framing separately. `httputil.ReverseProxy` also has deliberate mutation semantics around hop-by-hop headers, `X-Forwarded-*`, Host, and malformed query strings. The listener must therefore capture evidence before forwarding and must not describe forwarded traffic as byte-for-byte identical to the original wire representation.

## Decision

Add a provider-neutral local listener that performs this pipeline:

```text
provider CLI / developer tunnel / local sender
                    │
                    ▼
             WireLinter listener
                    │
          capture inbound evidence
                    │
                    ▼
           exact request body bytes
           exact observed raw query
           semantic request headers
                    │
                    ├────> canonical Trace
                    │
                    ▼
            controlled forwarding
                    │
                    ▼
             application endpoint
                    │
                    ▼
             response capture
                    │
                    ▼
              Trace completed
                    │
                    ▼
            pack -> engine -> Report
```

`listen` is an acquisition path. It MUST NOT contain a second diagnostic engine.

## CLI shape

Initial user-facing shape:

```bash
wirelint listen \
  --provider stripe \
  --forward-to http://127.0.0.1:3000/webhooks/stripe
```

Default bind address:

```text
127.0.0.1:4545
```

The developer can then point a provider-native tool at WireLinter. For Stripe:

```bash
stripe listen --forward-to http://127.0.0.1:4545/
```

The signing secret printed by Stripe CLI is the secret that must be used for the forwarded local delivery. WireLinter resolves that through the same environment-variable boundary already used by `lint`.

## Safety defaults

### Loopback listener

The listener binds only to loopback by default. Binding to wildcard or non-loopback interfaces requires an explicit unsafe/public-listen opt-in.

This avoids accidentally exposing a local diagnostic endpoint to a LAN or container network.

### Local forwarding target

The forwarding target is restricted to `localhost`, loopback IPv4, or loopback IPv6 by default. Forwarding to a non-loopback host requires an explicit opt-in.

This prevents an invocation intended for local development from silently exfiltrating webhook payloads, authorization headers, or signature material to a remote host.

### No persistence by default

Raw webhook payloads can contain customer data, addresses, email addresses, payment metadata, and other sensitive information.

The listener analyzes each Trace in memory and does not persist it by default. An explicit `--save-dir` option may persist canonical Trace JSON for reproduction/debugging.

### No active provider calls

`listen` never calls a provider API to create, mutate, resend, or trigger an event. Active scenarios belong to a later probe design with provider-specific safety semantics.

## Request body fidelity

The listener reads the inbound request body once, before forwarding, under a hard size limit.

If the body is completely read within the configured limit:

```text
bodyFidelity = exact
```

The same byte slice is:

1. recorded in the Trace;
2. hashed for deterministic evidence;
3. used as the body of the forwarded request.

WireLinter never parses JSON and then reserializes it for forwarding.

The initial default maximum request body is 16 MiB and is configurable. A body that exceeds the limit is rejected and is not forwarded as if it had been captured exactly.

## Query fidelity

The incoming `URL.RawQuery` is recorded before forwarding and is treated as the exact observed query component from Go's parsed request target.

Decoded ordered query items are derived separately for rule convenience. Failure to decode a query item MUST NOT alter `rawQuery`.

The forwarding target may not itself contain a query string in the initial implementation. The inbound raw query is copied to the target URL exactly. This avoids ambiguous query-merging rules.

## Headers

The Trace stores the semantic request headers observed by Go's server API. This is not a claim about original casing or wire order.

The forwarding request is deliberately different evidence. It:

- preserves end-to-end application/provider headers, including signature headers;
- does not inject an `X-WireLinter-*` header;
- strips RFC hop-by-hop headers;
- strips inbound `Forwarded` and `X-Forwarded-*` values rather than forwarding attacker-controlled proxy identity;
- lets the target URL determine the outbound Host value.

The original inbound semantic headers remain untouched in the Trace.

## Why not use ReverseProxy as the evidence model

`httputil.ReverseProxy` is useful infrastructure, but its rewrite behavior is not the canonical evidence source. Current Go documentation states that the Rewrite path removes `Forwarded` / `X-Forwarded-*` headers before rewriting and can remove unparsable query parameters unless the caller explicitly preserves `RawQuery`.

WireLinter therefore captures the inbound request first and performs forwarding explicitly. The forwarding implementation may reuse standard-library transport behavior, but a transformed outbound request never replaces the original Envelope request evidence.

## Redirects

The forwarding client does not follow redirects.

A `302`, `307`, or other redirect is the webhook handler's actual response and must be returned to the provider/sender and recorded as such. Following it would create behavior the provider did not observe and could replay request bodies unexpectedly.

## Response capture

The app response is streamed back to the sender while WireLinter observes status, semantic headers, protocol, duration, and response bytes up to a bounded capture limit.

The initial response capture limit is 1 MiB. If a response exceeds that capture budget, forwarding continues but the Trace must not claim exact response-body fidelity.

Transport automatic decompression is disabled so captured response bytes are the bytes received from the application transport layer rather than a transparently decompressed replacement.

## Timeouts and resource bounds

The listener uses explicit bounds instead of `http.ListenAndServe` defaults:

- request-header timeout;
- request-body read deadline;
- idle timeout;
- outbound response-header / total request timeout;
- maximum header bytes;
- maximum inbound body bytes;
- maximum response capture bytes.

These defaults are for a development diagnostic server, not a production reverse proxy.

## Trace lifecycle

One inbound delivery produces one canonical Trace in the initial implementation.

This keeps persistence atomic and makes each saved artifact replayable. Future session/grouping metadata can associate multiple deliveries without changing the underlying Envelope semantics.

At minimum, acquisition records observations such as:

```text
request.received
response.received
forward.failed
```

Operational forwarding failure and integration rule failure remain distinct. A valid Stripe signature can coexist with an unreachable local app, and the report must not rewrite one fact into the other.

## Concurrency

HTTP deliveries may arrive concurrently. Trace construction is request-local. Shared terminal output and optional file persistence must be synchronized so one delivery cannot corrupt another delivery's report/artifact.

## Non-goals for the first listener

- public tunneling;
- TLS certificate issuance;
- active event generation;
- automatic Stripe CLI process management;
- provider-specific URL routing;
- side-effect assertions;
- replay;
- browser UI;
- long-term traffic database.

These can be added only if they preserve the same canonical Trace and evidence-fidelity boundaries.

## Consequences

The developer gets a language-neutral workflow:

```text
real delivery -> WireLinter -> Python/Node/Go/Java/PHP app
```

No SDK is required in the application. The provider pack remains responsible for semantics; the listener remains responsible only for bounded acquisition and transparent-enough forwarding with explicit fidelity claims.
