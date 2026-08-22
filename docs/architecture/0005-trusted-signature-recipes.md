# ADR 0005 — Trusted declarative signature recipes

Status: **Proposed — implementation blocked until the reference model and negative cases are green**

This ADR defines the narrow extension WireLinter should use for webhook signature verification. It is intentionally not a general-purpose transformation language and it is not an SDK-emulation framework.

The model is derived from current official behavior of Stripe, Shopify, GitHub, Mercado Pago, and the Standard Webhooks specification/reference implementation. These mechanisms are architecture tests: if one requires provider-specific branches in trusted runtime code, the recipe model has failed.

## 1. Product requirement

A provider pack must be able to describe how an authentic webhook signature is constructed and verified without:

- arbitrary JavaScript/Python/Go callbacks;
- cryptography implemented in CEL;
- `if provider == "stripe"` branches in core;
- reconstructing exact bytes from parsed JSON;
- silently choosing among duplicated HTTP inputs;
- treating missing evidence as an invalid signature;
- exposing secrets or derived key material in reports.

Trusted core code implements bounded source extraction, parsing, message assembly, cryptography, freshness checks, and constant-time comparison. Packs compose those primitives declaratively.

## 2. Protocol versioning

Provider Pack Protocol `1.0` remains immutable and supports passive CEL / JSON Schema rules only.

Signature recipes are proposed for **Pack Protocol `1.1`**.

Compatibility policy:

- a runtime supporting `1.1` MUST also load valid `1.0` packs;
- a `1.0` runtime MUST reject a `1.1` pack rather than silently ignore signature mechanisms;
- `1.1` may add signature definitions and a `signature` rule kind without changing `1.0` semantics;
- no scenario/probe DSL is included in `1.1`.

## 3. What the recipe is authoritative about

WireLinter should not pretend every official SDK accepts malformed input identically. The pack defines a **provider behavior contract for valid deliveries plus conservative handling of ambiguous evidence**.

Source priority:

1. current provider specification/documentation for the protocol contract;
2. current official SDK/reference implementation when documentation is incomplete or operational behavior matters;
3. official tests/releases/commits when documentation and implementation conflict;
4. pack metadata documents the selected behavior revision and rationale.

The runtime never chooses between conflicting sources. A pack release makes that choice explicitly and cites it.

For malformed or ambiguous inputs that providers are not expected to emit, Pack 1.1 prefers deterministic conservative semantics over reproducing permissive SDK quirks. Example: a single-valued timestamp appearing twice is `ambiguous-signature-input`; core does not silently pick the first or last value just because one SDK happens to do so.

## 4. Reference behavior matrix

| Mechanism | Secret material | Signed message | Candidate extraction | Encoding | Freshness represented by reference recipe | Required evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Stripe | secret UTF-8 bytes | `timestamp + "." + exact body` | comma-delimited `Stripe-Signature`, all `v1` fields | hex | max age 300s; **no future bound** in current Go/Node validators | exact body; complete/observed signature header; `t` |
| Shopify | secret UTF-8 bytes | exact body | whole `X-Shopify-Hmac-Sha256` | base64 | none in HMAC check | exact body; HMAC header |
| GitHub | secret UTF-8 bytes | exact body | whole `X-Hub-Signature-256`, fixed `sha256=` prefix | hex after prefix | none in signature check | exact body; signature header |
| Mercado Pago | secret UTF-8 bytes | optional `id:<data.id>;` + optional `request-id:<x-request-id>;` + `ts:<ts>;` | comma-delimited `x-signature`, `v1` field | hex | none in baseline recipe; current Go SDK exposes an optional tolerance mode | signature header plus semantic query/header inputs used by manifest |
| Standard Webhooks | strip `whsec_`, base64-decode key | `webhook-id + "." + webhook-timestamp + "." + exact body` | space-delimited versioned entries, all `v1` values | base64 | ±300s | exact body; id/timestamp/signature headers |

The same compiler/evaluator must express all rows without provider-specific runtime code.

## 5. Important Mercado Pago compatibility finding

Current public Mercado Pago documentation has pages that still instruct consumers to lowercase alphanumeric `data.id` before building the signature manifest.

However, current official SDK behavior was changed in June 2026 to preserve the original `data.id` casing because the notification is signed using the original value. Current official Go tests explicitly exercise uppercase IDs, and the Python 3.3.0 release notes record the same correction.

Therefore the current WireLinter Mercado Pago reference recipe preserves `data.id` case.

This is not permission to casually override documentation. The eventual provider pack must record multiple official source references and a dated behavior revision so that the decision is auditable and replaceable by a later pack version if the provider converges on different behavior.

This finding is why signature recipes contain `sourceRefs[]` instead of one prose documentation URL.

## 6. Proposed Pack 1.1 shape

A pack adds named signature mechanisms:

```yaml
packProtocol: "1.1"

signatures:
  webhook-v1: signatures/webhook-v1.yaml
```

A rule references the mechanism:

```yaml
schemaVersion: 1
id: WL-ST-SIGNATURE
kind: signature
scope: envelope
severity: error
stability: preview
title: Stripe webhook signature must be valid
signatureRef: webhook-v1
docsRef: webhook-signatures
```

One rule may produce stable sub-reasons through `messageId`, for example:

```text
missing-signature
malformed-signature
missing-signature-input
ambiguous-signature-input
signature-mismatch
timestamp-stale
timestamp-future
secret-unavailable
insufficient-body-fidelity
insufficient-header-evidence
insufficient-query-evidence
```

This matches the SARIF concept of one stable rule ID with stable message IDs rather than inventing a rule for every failure reason.

## 7. Signature recipe is a bounded dataflow

Conceptual stages:

```text
trusted secret
      │
      ▼
source extraction ──> typed bindings
      │
      ▼
message assembly
      │
      ▼
trusted HMAC-SHA256
      │
      ▼
candidate decoding + constant-time comparison
      │
      └── optional directional freshness checks against Envelope.receivedAt
```

There is no arbitrary transform pipeline in protocol 1.1.

## 8. Evidence and HTTP header multiplicity

Header names are matched ASCII case-insensitively. Header values are semantic application-level evidence, as defined by ADR 0004; they are not reconstructed wire bytes.

A present header value may be used even when `headersCompleteness` is `partial`.

For a requested header that is absent:

- `headersCompleteness: complete` -> absence is proven;
- `partial` / `unavailable` -> result is `open`, because absence is not observable.

For direct header bindings, cardinality is explicit:

```text
exactly-one
zero-or-one
one-or-more
```

For a parser's source header, Pack 1.1 intentionally allows only **`exactly-one`**. The runtime MUST NOT concatenate, comma-join, take-first, or take-last repeated header entries implicitly.

If two semantic header entries exist for a parser source that is declared exactly-one, the result is `fail` with `ambiguous-signature-input`.

## 9. Source parsers

### 9.1 Direct header and query bindings

Query parameter names remain case-sensitive.

A semantic query binding may use decoded query values when `queryFidelity` is `exact` or `reconstructed`, because the mechanism needs the parameter value rather than raw query bytes.

If query fidelity is `unavailable`, absence of a required query input is not observable.

A future mechanism that signs raw query text must declare exact raw-query fidelity instead of reusing semantic query bindings.

### 9.2 Exact raw body

A raw-body binding can require:

```text
bodyFidelity == exact
```

If exact body bytes are unavailable, the signature rule is `open`; the runtime must never serialize `decodedBody` and pretend those bytes were signed by the provider.

### 9.3 `delimited-pairs`

Pack 1.1 proposes one bounded parser for Stripe, Mercado Pago, and Standard Webhooks metadata:

```text
delimited-pairs
```

Configuration is limited to:

```text
source header: name + exactly-one cardinality + optional outer trim
item delimiter: one character
key/value delimiter: one character
trim key/value surrounding whitespace: boolean
```

Examples:

```text
Stripe / Mercado Pago
item delimiter: ","
pair delimiter: "="

Standard Webhooks
item delimiter: " "
pair delimiter: ","
```

The parser preserves field order and duplicate keys. A field binding then declares cardinality.

Pack 1.1 parsing is deliberately strict: empty items, missing key/value delimiter, empty keys, or structurally ambiguous pairs make the signature metadata malformed. Unknown but structurally valid keys remain available and are ignored unless referenced by a binding.

Runtime constants cap source-header bytes, parsed item count, binding count, and signature-candidate count. Packs cannot raise those limits.

## 10. Typed bindings

Recipe bindings are one of:

- UTF-8 string;
- exact byte string;
- ordered string list.

Conceptual Stripe example:

```yaml
parsers:
  signature-fields:
    sourceHeader:
      name: Stripe-Signature
      cardinality: exactly-one
    format:
      type: delimited-pairs
      itemDelimiter: ","
      pairDelimiter: "="
      trimSpace: false

bindings:
  timestamp:
    fromField:
      parser: signature-fields
      key: t
      cardinality: exactly-one

  candidates:
    fromField:
      parser: signature-fields
      key: v1
      cardinality: one-or-more

  body:
    fromRawBody:
      requireFidelity: exact
```

Conceptual Mercado Pago optional inputs:

```yaml
bindings:
  data-id:
    fromQuery:
      name: data.id
      cardinality: zero-or-one
      trimSpace: true

  request-id:
    fromHeader:
      name: x-request-id
      cardinality: zero-or-one
      trimSpace: true
```

`zero-or-one` means absence is a valid value-state only when the source was observable. It never means “ignore missing capture evidence”.

Protocol 1.1 has no lowercase/uppercase transform. The Mercado Pago casing correction demonstrates why casual normalization is dangerous.

## 11. Message assembly

Messages are an ordered sequence of:

- literal UTF-8 bytes;
- string bindings encoded as UTF-8;
- byte bindings such as exact request body;
- optional binding components with fixed prefix/suffix literals.

Stripe:

```yaml
message:
  - binding: timestamp
  - literal: "."
  - binding: body
```

Mercado Pago:

```yaml
message:
  - binding: data-id
    prefix: "id:"
    suffix: ";"
    omitIfAbsent: true
  - binding: request-id
    prefix: "request-id:"
    suffix: ";"
    omitIfAbsent: true
  - binding: timestamp
    prefix: "ts:"
    suffix: ";"
```

The runtime should stream segments directly into the MAC rather than concatenate another copy of a potentially large body.

List-valued bindings cannot be used as message segments in Pack 1.1.

## 12. Secret decoding

A recipe references a secret declared by the provider pack; it never contains the secret itself.

Protocol 1.1 requires only:

```text
utf8
prefixed-base64
```

`prefixed-base64` supports Standard Webhooks-style `whsec_<base64>` material. The fixed prefix is part of the declared representation and must be present; the remainder is base64-decoded into key bytes.

A configured secret that is present but malformed for its declared representation is a local configuration/execution error (exit 2), not an integration failure.

A secret that was not supplied makes only that signature result `open` with `secret-unavailable`; other rules still run.

Secrets, source secret strings, and derived key bytes are never serialized into Trace/Report and must be redacted from errors/logs.

## 13. Cryptography and candidates

Pack Protocol 1.1 exposes exactly one MAC algorithm:

```text
hmac-sha256
```

Implementation lives in trusted core using the platform crypto library. Packs cannot implement cryptography in CEL or disable constant-time comparison.

Candidate encodings required by the reference set:

```text
hex
base64-standard
```

A candidate set may declare a fixed textual prefix to strip before decoding, covering GitHub's `sha256=` value without provider-specific code.

Candidate evaluation policy:

1. extract the ordered candidate list with bounded count;
2. apply the fixed prefix requirement, if any;
3. decode each candidate independently;
4. compare every successfully decoded candidate to the computed MAC using constant-time equality;
5. if any candidate matches -> `pass`;
6. if candidates were present but none were decodable -> `fail / malformed-signature`;
7. if at least one candidate decoded but none matched -> `fail / signature-mismatch`.

A malformed sibling candidate does not override a valid matching candidate. This is important for rotation/multi-signature headers and prevents junk appended beside a valid candidate from forcing a false negative.

## 14. Freshness is directional and separate from MAC validity

Freshness is optional and does not redefine whether the MAC is authentic.

Pack 1.1 uses independent directional bounds:

```yaml
freshness:
  timestampBinding: timestamp
  format: unix-seconds
  reference: envelope-received-at
  maxAgeSeconds: 300
  maxFutureSeconds: 300
```

Semantics:

- `maxAgeSeconds` present -> reject when `receivedAt - timestamp` exceeds the bound;
- `maxFutureSeconds` present -> reject when `timestamp - receivedAt` exceeds the bound;
- omitted direction -> no check in that direction.

This distinction is necessary because current official behavior differs:

- Stripe's current Go and Node validators enforce a maximum **age** but do not reject a future timestamp solely for being ahead of the clock;
- the Standard Webhooks Go reference rejects both too-old and too-new timestamps;
- current Mercado Pago Go supports optional tolerance, but no tolerance is enabled by default, so the baseline reference recipe does not invent one.

The reference instant for offline evidence is **`Envelope.receivedAt`**, not the wall clock when a saved Trace is linted later. This keeps replay deterministic.

## 15. Evidence-to-result policy

Signature evaluation follows ADR 0003 and ADR 0004.

### `pass`

Required evidence was observable, the mechanism evaluated successfully, at least one candidate matched, and configured freshness checks passed.

### `fail`

Evidence is sufficient and a protocol problem is proven, for example:

- required signature header absent from a complete header set;
- parser source occurs more than once despite exactly-one cardinality;
- signature metadata is syntactically malformed;
- candidate signatures are malformed or do not match;
- timestamp violates a configured directional bound.

### `open`

The mechanism is valid but evidence/configuration is insufficient, for example:

- exact raw body required but only reconstructed/unavailable bytes exist;
- required header absent from partial/unavailable capture;
- semantic query input not observable;
- webhook secret not supplied.

### execution error

The mechanism itself cannot be trusted/executed, for example:

- recipe schema/semantic model invalid;
- referenced parser/binding/source does not exist;
- configured local secret violates its declared representation;
- internal invariant fails.

These states must never collapse into `signature-mismatch`.

## 16. Stable message IDs

Initial generic vocabulary:

```text
missing-signature
malformed-signature
missing-signature-input
ambiguous-signature-input
signature-mismatch
timestamp-stale
timestamp-future
secret-unavailable
insufficient-body-fidelity
insufficient-header-evidence
insufficient-query-evidence
```

The provider pack supplies human wording/remediation. Automation can rely on `(ruleId, messageId)`.

## 17. Source provenance

Signature definitions contain:

```yaml
sourceRefs:
  - webhook-signature-docs
  - sdk-behavior-2026-06
```

Every key must resolve through the provider pack's official source/document map before a 1.1 pack is accepted.

Provider behavior conflicts are resolved by a new pack release with a documented rationale. The runtime never fetches provider docs during evaluation and never dynamically decides which source is “newer”.

Mercado Pago's case-preservation decision should cite both public notification documentation and official SDK/release evidence of the June 2026 correction.

## 18. Standard Webhooks is a reference mechanism, not a provider shortcut

Standard Webhooks independently exercises:

- prefixed + base64-decoded secret material;
- exact body input;
- multiple versioned signatures for rotation;
- base64 candidates;
- timestamp freshness in both directions.

The Standard Webhooks specification also supports asymmetric `v1a` signatures. Pack 1.1 intentionally does not implement asymmetric signatures yet; a symmetric recipe selects `v1` entries and ignores structurally valid unreferenced versions.

Shopify may expose `Webhook-*` metadata in newer flows while its documented HTTPS authenticity check remains `X-Shopify-Hmac-SHA256` over the raw body. WireLinter models the actual mechanism selected by the provider pack rather than inferring a protocol from header names.

## 19. Deliberate exclusions from protocol 1.1

Do not add until a real provider proves the need:

- asymmetric signatures;
- arbitrary digest/MAC algorithms;
- regex parsers;
- arbitrary split/replace/transform pipelines;
- arbitrary charset conversion;
- case normalization;
- callbacks or embedded provider code;
- CEL-based cryptography;
- RFC 9421 HTTP Message Signatures composition;
- Wasm extensions;
- active probe/scenario definitions.

Every future primitive must be justified by a real mechanism and retain deterministic, bounded, sandboxed execution.

## 20. Implementation gate

Do not implement the signature evaluator until all of the following are true:

1. `signature-v1.schema.json` validates fixture-only definitions for Stripe, Shopify, GitHub, Mercado Pago, and Standard Webhooks;
2. semantic validation rejects dangling references, list bindings in message assembly, optional candidate sets, ambiguous parser source semantics, and invalid freshness bindings;
3. Stripe fixture encodes max-age-only freshness;
4. Standard Webhooks fixture encodes bidirectional freshness;
5. Mercado Pago fixture preserves mixed-case `data.id` by construction;
6. parser source header cardinality is explicit and never implicitly merged;
7. no fixture requires provider-specific runtime code.

Required architecture test:

```text
same generic compiler/evaluator
        │
        ├── Stripe fixture
        ├── Shopify fixture
        ├── GitHub fixture
        ├── Mercado Pago mixed-case data.id fixture
        └── Standard Webhooks multiple-signature fixture
```

Only after this gate is green should the trusted signature evaluator be implemented. Stripe should then be the first real Pack Protocol 1.1 provider pack, not a hard-coded special case.
