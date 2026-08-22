# ADR 0011 — Evidence-aware CEL rule lifecycle

Status: **Accepted for implementation**

## Context

WireLinter's public result model distinguishes four trustworthy outcomes:

```text
pass
fail
open
notApplicable
```

The existing CEL rule lifecycle can only express three of them cleanly:

- `when == false` -> `notApplicable`
- `assert == true` -> `pass`
- `assert == false` -> `fail`

This becomes a correctness problem as soon as provider packs inspect evidence that may legitimately be absent.

For example, webhook acknowledgement policies differ by provider:

- GitHub requires a successful 2xx response within its documented delivery timeout;
- Shopify HTTPS webhooks use a different timing/retry policy;
- Mercado Pago documents 200/201 acknowledgement and its own timing/retry schedule.

The status and duration checks themselves are ordinary boolean policy. They do not justify a trusted `response-policy` primitive in the Go core.

However, a saved/imported Trace may not contain a response at all. In that case:

```text
assert: envelope.response.status >= 200
```

must not become `fail` merely because the capture lacked response evidence. It also must not be hidden behind `when` and reported as `notApplicable`, because the provider policy *does* apply; WireLinter simply cannot prove the outcome.

Header rules have the same problem. A missing `X-GitHub-Delivery` in a capture whose `headersCompleteness` is `partial` is not proof that GitHub omitted the header.

## Research

CEL itself distinguishes errors from unknown values and supports partial evaluation. CEL-Go exposes `PartialVars`, `AttributePattern`, and `OptPartialEval` for host-declared unknown attributes.

That facility is useful when the host already knows exactly which nested attributes are unknown. It does not automatically infer the semantic evidence requirements of an arbitrary provider rule. Deriving missing nested attributes from the expression AST would create a second implicit rule language and make pack behavior harder to audit.

CEL-Go also provides the official Strings extension, including ASCII-only case conversion with runtime cost accounting. HTTP header field names are ASCII case-insensitive, so `lowerAscii()` is a suitable portable expression primitive for semantic header comparisons.

A separate runtime issue appears when reusing WireLinter's JSON Schema normalization directly as CEL input. `jsonschema/v6` intentionally preserves JSON numbers as `json.Number` to avoid precision loss. CEL does not treat Go `json.Number` as one of its native numeric values, so expressions such as `envelope.response.status >= 200` fail at runtime with an overload error even when the underlying JSON token is `500`.

This must not be fixed by globally decoding all JSON numbers as `float64`: doing so would weaken the precision-preserving representation used by JSON Schema.

## Decision

Pack Protocol `1.2` adds an explicit **evidence sufficiency stage** to CEL rules.

A CEL rule may declare:

```yaml
when: <optional applicability CEL>
requires: <optional evidence-sufficiency CEL>
assert: <required correctness CEL>
```

The lifecycle is strictly ordered:

```text
when == false       -> notApplicable
requires == false   -> open
assert == true      -> pass
assert == false     -> fail
```

Any CEL runtime/type/cost error remains an **execution failure**, not a provider result.

This keeps result semantics orthogonal:

- `when` answers: *does this policy apply to this integration evidence?*
- `requires` answers: *do we have enough evidence to decide?*
- `assert` answers: *does the observed integration satisfy the policy?*

### CEL and JSON Schema use separate evidence views

The canonical Trace remains one data model, but the engine derives two in-memory views for rule evaluation:

```text
canonical Trace
    │
    ├── precision-preserving JSON view -> JSON Schema + JSON Pointer evidence
    │                                  numbers remain json.Number
    │
    └── CEL-native JSON-shaped view    -> when / requires / assert
                                       integers -> int64
                                       fractions/exponents -> finite double
```

Integral JSON tokens are converted to `int64` only when representable exactly. Fractional/exponent-form JSON tokens are converted to finite `float64`/CEL double. A number outside those domains is an execution-time normalization error rather than a silently rounded CEL value.

This split preserves the stronger number semantics of JSON Schema while giving CEL values its runtime can actually compare.

Pack authors that need arbitrary-precision numeric constraints should use JSON Schema. CEL remains appropriate for bounded semantic policy over representable runtime values such as HTTP status, duration, counts, flags, and ordinary provider payload fields.

### Example: acknowledgement status

```yaml
schemaVersion: 1
id: WL-GH-ACK-001
kind: cel
scope: envelope
severity: error
stability: stable
title: Webhook acknowledgement status
requires: has(envelope.response)
assert: envelope.response.status >= 200 && envelope.response.status < 300
evidencePointers:
  - /response/status
messages:
  evidence-unavailable: >-
    No application response was captured, so acknowledgement status cannot be decided.
docsRef: webhooks-troubleshooting
```

A capture with no response produces:

```text
open / evidence-unavailable
```

A captured HTTP 500 produces:

```text
fail
```

A captured HTTP 204 produces:

```text
pass
```

### Example: case-insensitive required header

Protocol 1.2 CEL environments include the official CEL-Go Strings extension at version 5.

```yaml
requires: envelope.request.headersCompleteness == "complete"
assert: >-
  envelope.request.headers.exists(
    h,
    h.name.lowerAscii() == "x-github-delivery" && h.value != ""
  )
```

If header capture is partial, the rule is `open`. If capture is complete and the header is missing, the rule is `fail`.

## Why not a response/ACK primitive

Provider acknowledgement differences are policy data over already-normalized evidence:

```text
status
response duration
possibly event/topic applicability
```

They do not require cryptography, byte reconstruction, candidate parsing, or constant-time comparison.

Those requirements justified a trusted signature primitive. Response policy does not.

Keeping acknowledgement rules in CEL means provider packs can encode differences without growing a trusted Go switch statement or a generic-but-rigid ACK DSL.

A trusted primitive should be added only when a real mechanism cannot be expressed safely and deterministically with the existing contract.

## Why not use `when` for missing evidence

`notApplicable` and `open` have different meaning.

A GitHub acknowledgement rule applies to the delivery even if the imported capture omitted the response. Marking that case `notApplicable` would hide a gap in evidence and distort coverage reporting.

## Why not infer unknowns automatically

WireLinter does not inspect CEL ASTs and guess which missing fields should be treated as unknown provider evidence.

Reasons:

1. absence can mean different things by rule;
2. a typo in an expression must remain an execution/pack defect, not silently become unknown evidence;
3. expressions can derive requirements through comprehensions and logical operators;
4. explicit `requires` is reviewable in YAML and has stable semantics across future CEL implementations.

CEL partial evaluation remains a possible future optimization/tooling feature, not the rule contract for evidence sufficiency.

## Protocol compatibility

Protocol 1.0 and 1.1 environments remain unchanged.

Protocol 1.2 adds:

- `requires` for `kind: cel` rules;
- CEL-Go Strings extension version 5 for 1.2 CEL expressions;
- signature recipes remain available exactly as in protocol 1.1;
- the explicit CEL-native numeric projection described above.

A 1.1 pack cannot use `requires` or 1.2-only CEL extensions and still claim protocol 1.1 compatibility.

The loader therefore compiles CEL against the environment selected by the manifest's declared protocol rather than silently enabling new expression features for old protocols.

## `open` result semantics

When `requires` evaluates to false:

```text
kind      = open
level     = none
messageId = evidence-unavailable
```

The rule may override the human message using:

```yaml
messages:
  evidence-unavailable: "..."
```

The core owns the stable `messageId`; packs own provider-specific explanation text.

No failure evidence pointers are resolved in the `open` path. `evidencePointers` remain proof locations for a concrete `fail` result. Because the public Report contract requires evidence for `open`, the engine cites the existing rule subject root (`/envelopes/N` for envelope rules or the Trace root) as proof of the capture that was insufficient; it does not invent a JSON Pointer for a field that was absent.

## Applicability ordering

`when` is evaluated **before** `requires`.

This is important for provider contracts where a rule genuinely does not apply to a topic/event. A rule that is inapplicable should not become `open` merely because evidence needed only by the inapplicable assertion is absent.

Pack authors must keep `when` limited to evidence expected to exist for applicability classification. A `when` evaluation error is an execution failure and must not be downgraded to `open`.

## Consequences

The rule engine gains a general evidence-awareness mechanism without adding provider-specific code.

This is sufficient to express response status/timing policies and complete-capture header requirements while preserving honest uncertainty.

It also creates a clear design test for future primitives:

```text
Can the rule be expressed as applicability + evidence sufficiency + CEL assertion?
    yes -> keep it in the pack
    no  -> research a bounded trusted primitive
```
