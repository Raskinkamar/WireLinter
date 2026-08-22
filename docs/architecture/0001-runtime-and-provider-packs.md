# RFC 0001 — Runtime, traces, and provider packs

Status: **Proposed**

This RFC defines the architecture WireLinter should converge on before the Go experiment is merged.

## 1. Product boundary

WireLinter is **not** a generic API fuzzer, OpenAPI linter, mock server, or contract broker.

Its job is to verify the operational semantics of third-party integrations, especially event-driven integrations:

- exact-byte signature verification;
- authentication/header requirements;
- acknowledgement behavior and latency;
- retry semantics;
- duplicate delivery handling;
- delivery identity and replay safety;
- event ordering assumptions;
- payload/provider version drift;
- deterministic replay of failures;
- framework-specific remediation after the protocol-level diagnosis is known.

OpenAPI/schema tooling, contract testing, and generic fuzzing are complementary inputs rather than the product core.

## 2. Research-driven decisions

### 2.1 A versioned boundary between core and provider logic

Mature extensible CLIs separate a stable core from domain-specific behavior with a versioned contract. WireLinter should do the same.

Provider packs MUST declare a `packProtocol` version independent from the WireLinter CLI version. A future registry or runtime must be able to reject incompatible packs deterministically.

### 2.2 Do not invent a general-purpose rule language

WireLinter should compose existing standards instead:

- **JSON Schema** for payload structure;
- **CEL (Common Expression Language)** for safe, bounded assertions over normalized evidence;
- declarative built-in primitives for cryptographic signatures, timestamps, encodings, header lookup, raw-body access, retry identity, and response constraints.

CEL is intentionally non-Turing-complete, side-effect-free, portable, and designed to be embedded with host-provided functions. That is a much better fit than arbitrary JavaScript/Python callbacks for community-authored rules.

### 2.3 WebAssembly is an escape hatch, not the first plugin system

Some providers will eventually require logic that cannot be expressed cleanly with schemas + CEL + built-ins. If that becomes a real need, advanced provider extensions should use a **versioned WebAssembly Component Model / WIT interface** rather than language-specific plugins.

Do not implement Wasm plugins until at least one real provider requires them.

### 2.4 One executable, language-neutral target

The primary CLI may be implemented in Go because it can ship as a standalone binary, but the application under test is a black-box HTTP system. Python, Node, PHP, Java, Go, Ruby, Rust, .NET, or another runtime must make no difference to the protocol engine.

Framework-specific code appears only in remediation hints.

## 3. Canonical data model

All commands MUST converge on the same evidence model instead of implementing their own check logic.

### 3.1 Envelope

An `Envelope` represents one exact integration delivery.

Required conceptual fields:

```text
Envelope
├── provider
├── event_type
├── delivery_id
├── received_at
├── request
│   ├── method
│   ├── url
│   ├── headers (lossless, case-insensitive view available)
│   ├── query
│   ├── raw_body bytes
│   └── decoded_body optional
└── response optional
    ├── status
    ├── headers
    ├── raw_body
    └── duration
```

`raw_body` is first-class. The normalized JSON object can never replace it because signature algorithms commonly operate on exact bytes.

### 3.2 Observation

An `Observation` records something WireLinter learned while exercising or observing an integration.

Examples:

```text
request.sent
response.received
signature.validated
delivery.repeated
connection.failed
side_effect.reported
```

Each observation has a timestamp and references the Envelope or scenario step that produced it.

### 3.3 Trace

A `Trace` is an ordered collection of Envelopes + Observations representing one test or real delivery sequence.

This is the central abstraction.

```text
capture.json   ─┐
probe          ─┤
listen/proxy   ─┼─> Trace -> provider pack -> findings
replay         ─┤
CI fixture     ─┘
```

If `lint`, `probe`, `listen`, and `replay` do not share this model, the product will fragment.

### 3.4 Finding

A finding must contain evidence, not only prose.

```text
Finding
├── rule_id
├── severity
├── provider
├── title
├── explanation
├── evidence_refs[]
├── docs_ref
├── remediation_key optional
└── stability: stable | preview | deprecated
```

Stable rule IDs are part of the public interface.

## 4. Provider pack model

A provider pack is data-first and capability-declared.

Proposed layout:

```text
packs/stripe/
├── pack.yaml
├── schemas/
│   └── event.json
├── rules/
│   ├── signature.cel
│   ├── acknowledgement.cel
│   ├── duplicates.cel
│   └── ordering.cel
├── scenarios/
│   ├── valid-delivery.yaml
│   ├── invalid-signature.yaml
│   ├── duplicate-delivery.yaml
│   └── out-of-order.yaml
├── fixtures/
└── remediation/
    ├── express.md
    ├── fastapi.md
    └── spring.md
```

### 4.1 `pack.yaml`

Conceptual schema:

```yaml
id: stripe
name: Stripe
packVersion: 0.1.0
packProtocol: 1
providerDocsRevision: "2026-08"
capabilities:
  - passive-lint
  - active-probe
  - replay
secrets:
  webhook_secret:
    env: STRIPE_WEBHOOK_SECRET
signature:
  scheme: hmac-sha256
  source: raw_body
```

The actual schema should be versioned before external packs are accepted.

### 4.2 Built-in protocol primitives

Provider packs should describe common protocols instead of reimplementing them in Go.

Initial primitives should include:

```text
header(name)
query(name)
raw_body
json(path)
hmac_sha256(secret, bytes)
hex(bytes)
base64(bytes)
constant_time_equal(a, b)
timestamp(value)
response.status
response.duration
same_delivery_id(a, b)
```

Provider-specific message construction can combine these primitives with CEL expressions.

Cryptographic implementations remain in trusted core code; packs describe how they are composed.

## 5. Scenario engine

A single request is insufficient for many integration bugs. Retry, duplicate, and ordering behavior are inherently multi-step.

A `Scenario` is a deterministic sequence of stimuli and assertions.

Example concept:

```yaml
id: duplicate-delivery
steps:
  - send: valid_event
    delivery_id: evt_123
  - send: valid_event
    delivery_id: evt_123
assert:
  - response.all_2xx
  - cel: trace.deliveries.filter(d, d.id == "evt_123").size() == 2
  - side_effect.max_count: 1
```

Not every assertion can be proven from HTTP alone. Side-effect assertions require an optional observer/SDK hook and MUST be marked `not-observable` rather than guessed when no observer exists.

## 6. Commands are front ends over the same engine

### `lint`

Consumes a saved Trace or Envelope without network activity.

### `probe`

Runs active provider scenarios against a target the user controls and produces a Trace.

### `listen`

Receives real provider deliveries, stores exact bytes, optionally forwards them, and produces Traces.

### `replay`

Replays a previously captured Trace or selected delivery exactly, preserving bytes where possible.

### `check`

Runs the configured integration suite from `wirelint.yaml`, suitable for CI.

No command gets provider-specific hard-coded logic directly in its command handler.

## 7. Configuration and reproducibility

Proposed project config:

```yaml
version: 1
integrations:
  stripe-payments:
    provider: stripe
    endpoint: http://localhost:4242/webhook
    scenarios:
      - signature
      - duplicate-delivery
      - malformed-payload
```

When external provider packs exist, WireLinter should write a lock file that pins:

```text
pack id
pack version
pack protocol version
content digest
provider docs revision
```

Rule updates must not silently change CI results without an explicit pack update.

## 8. Framework remediation layer

Diagnosis and remediation are separate.

Core finding:

```text
WL-ST-SIG-002
Exact raw bytes were not verified successfully.
```

Framework remediation may then explain the likely fix for:

```text
Express
Fastify
NestJS
FastAPI
Django
Laravel
Spring
ASP.NET
```

The core must never infer a framework-specific root cause when evidence only proves a protocol failure.

## 9. Security model

Active probing is potentially destructive.

Required defaults:

- loopback-only targets unless remote probing is explicitly enabled;
- remote mode prints the target and requires an explicit flag;
- never accept secrets as plain positional/flag values;
- redact known secret values from reports and saved traces;
- cap response-body capture size;
- no automatic redirect following during security-sensitive probes;
- distinguish read-only probes from potentially side-effecting scenarios;
- future downloaded packs are data-only unless explicitly trusted;
- future executable extensions run in a sandboxed, capability-limited environment.

## 10. Go runtime decision

Go remains a good candidate for the primary runtime because WireLinter needs HTTP/TLS/proxying, concurrency, portable static binaries, and simple cross-compilation.

However, **Go is an implementation detail, not the extension model**.

The repository should support Go 1.25+ and test against both currently supported Go release lines. Release binaries may be built with the newest supported stable Go release.

## 11. What the current Go prototype gets wrong / leaves incomplete

The current draft branch is only an execution experiment. It MUST NOT be merged as the final architecture because:

- provider behavior is still hard-coded directly in Go;
- no canonical Trace exists yet;
- no pack protocol exists yet;
- no JSON Schema/CEL rule layer exists yet;
- multi-step retry/order scenarios are not modeled;
- findings do not yet reference evidence;
- distribution exists before pack/version semantics are stabilized.

The useful parts to retain are the black-box HTTP approach, local-first safety, exact-byte signing tests, portable binary experiment, and CI cross-compilation.

## 12. Implementation order

### Phase A — architecture foundation

1. define versioned Trace/Envelope/Finding schemas;
2. define `packProtocol: 1` manifest schema;
3. implement pack loader and validation;
4. integrate JSON Schema + CEL;
5. port Stripe as the reference pack only;
6. prove passive lint and active probe share the same Trace + rule engine.

### Phase B — operational semantics

1. scenario runner;
2. duplicate/retry sequences;
3. ordering scenarios;
4. timeout/ACK assertions;
5. optional side-effect observer contract.

### Phase C — real providers

Port providers one at a time with official-doc-backed rules and scenario tests. Do not claim support based on logo count.

### Phase D — ecosystem

1. stable standalone release;
2. thin npm/npx wrapper;
3. thin PyPI/uvx wrapper;
4. Homebrew/Winget/Docker;
5. SARIF/editor integrations.

### Phase E — advanced extensions only if demanded

Define a WIT interface and sandboxed WebAssembly component ABI only when a provider proves that schemas + CEL + core primitives are insufficient.

## 13. Success criterion

The architecture is successful when the same Stripe rule pack can:

- lint an offline capture;
- evaluate a live probe;
- inspect traffic captured by `listen`;
- replay a saved failure;
- emit identical rule IDs and evidence semantics in terminal, JSON, and CI;

without embedding Stripe-specific branching inside the CLI command code.
