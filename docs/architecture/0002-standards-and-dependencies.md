# ADR 0002 — Standards and dependency choices

Status: **Accepted for architecture foundation**

This decision record narrows the architecture described in RFC 0001 into concrete standards and dependencies. The goal is to avoid inventing formats or extension mechanisms when stable standards already exist.

## 1. Rule evaluation: CEL

Repository: `github.com/cel-expr/cel-go`.

Go module imported by release `v0.30.0`: `github.com/google/cel-go`.

This distinction is intentional. The project repository moved organizations in 2026, but the `v0.30.0` `go.mod` still declares `module github.com/google/cel-go`; Go dependencies and imports must follow the module declaration rather than the repository URL.

Initial version: `v0.30.0`.

Why:

- CEL is intentionally non-Turing-complete and side effect free;
- expressions can be compiled when a provider pack loads rather than interpreted ad hoc for every delivery;
- the runtime supports cost estimation/tracking and parser/checker limits;
- the language is portable across ecosystems and is not tied to Go as an extension language;
- CEL operates naturally over JSON-like maps/lists and normalized WireLinter evidence.

CEL is used for **assertions and applicability predicates**, not for arbitrary I/O, cryptographic implementation, or provider scripting.

Rejected for the initial architecture:

- arbitrary JavaScript/Python/Go callbacks: language-specific, difficult to sandbox, and non-deterministic as a public extension interface;
- Rego/OPA: strong technology, but larger and more policy-engine-oriented than the bounded provider assertions WireLinter needs;
- a custom expression language: unnecessary maintenance and interoperability burden.

## 2. Structural validation: JSON Schema Draft 2020-12

Use `github.com/santhosh-tekuri/jsonschema/v6`.

Initial version: `v6.0.2`.

JSON Schema validates:

- WireLinter's own Trace/Report/Pack/Rule contracts;
- provider payload shapes when a rule explicitly declares structural validation.

It does not replace CEL. JSON Schema answers "does this value have this structure?"; CEL answers semantic questions across headers, payload, response and a multi-delivery trace.

## 3. Exact locations: JSON Pointer, not CEL

Use RFC 6901 JSON Pointer whenever a rule needs to identify **one deterministic location** inside canonical evidence.

Examples:

```text
/envelopes/0/request/decodedBody
/envelopes/0/response/status
/observations/2/attributes/sideEffectCount
```

Consequences:

- `json-schema` rules use `targetPointer`, not a CEL expression, to choose the value to validate;
- findings use JSON Pointer for evidence locations;
- CEL remains available when selection is part of a semantic assertion rather than a single address.

RFC 9535 JSONPath is deliberately not required in pack protocol v1. It is a standardized, more powerful query language and may be added later if real rules need multi-node selection that CEL cannot express cleanly. We should not ship two overlapping query mechanisms without demonstrated need.

## 4. YAML authoring: stable parser, JSON-compatible semantics

Provider manifests/scenarios are human-authored YAML, but their semantic model must remain JSON-compatible so it can be schema-validated and hashed/reproduced consistently.

Use `github.com/goccy/go-yaml`.

Initial version: `v1.19.2`.

Why this instead of `go.yaml.in/yaml/v4` today:

- the YAML organization's v4 line is the correct long-term maintained upstream direction, but as of August 2026 its published v4 module is still release-candidate software;
- goccy/go-yaml has a stable v1 release line, YAML Test Suite coverage, strict unknown-field support, and duplicate-map-key errors by default;
- pack/config parsing is a trust boundary, so duplicate keys and ambiguous configuration must fail closed.

Loader requirements:

- exactly one YAML document;
- reject duplicate mapping keys;
- reject unknown fields after decoding into versioned structs;
- reject YAML values that do not round-trip into the JSON-compatible data model expected by the schema;
- apply JSON Schema validation after YAML decoding;
- reject aliases/constructs if they create ambiguous or unsafe semantics for the pack protocol.

The dependency choice can be revisited when the official YAML v4 line publishes a stable release; changing YAML parser must not change pack protocol semantics.

## 5. Event normalization: CloudEvents is optional interoperability, not the source of truth

CloudEvents provides a strong vendor-neutral event information model (`id`, `source`, `type`, `subject`, `time`, etc.) and HTTP bindings. WireLinter should be able to expose/adapt normalized event metadata using CloudEvents concepts where useful.

However, most third-party webhook providers do not send CloudEvents natively, and converting a delivery into a CloudEvent necessarily loses or abstracts transport details.

Therefore:

- the exact HTTP Envelope remains the source of truth;
- a provider pack MAY derive normalized event metadata;
- normalized event metadata never replaces raw headers, query text, or body bytes used by signature rules.

## 6. Telemetry interoperability: OpenTelemetry export, not canonical storage

OpenTelemetry has stable HTTP span conventions and is useful for correlating WireLinter execution with a user's observability stack.

But an OTel span is not a lossless HTTP capture format and is intentionally concerned with telemetry rather than exact request-byte reproduction.

Therefore:

- WireLinter Trace remains canonical evidence;
- future `--otel-export` / OTLP support may map WireLinter scenarios and requests into spans/events;
- WireLinter may retain external trace/span correlation identifiers as metadata;
- rules must never depend on an OpenTelemetry exporter being configured.

## 7. HTTP signatures

RFC 9421 HTTP Message Signatures is a standards-track mechanism for signing selected HTTP message components.

WireLinter should implement RFC 9421 as a first-class trusted primitive when provider support demands it. It does **not** replace custom Stripe/Shopify/GitHub/Mercado Pago signing schemes, which must be represented by narrow declarative signature recipes backed by trusted core cryptographic primitives.

Crypto itself is never implemented in CEL or downloaded data packs.

## 8. Provider-pack distribution: OCI is the preferred future direction

Do not implement a custom registry in Phase A.

If/when community provider packs need remote distribution, evaluate OCI Distribution as the default transport because it is content-type agnostic and already provides content-addressed digests, tags and widespread registry infrastructure.

This would allow concepts such as:

```text
ghcr.io/wirelint/packs/stripe:1.2.0
ghcr.io/wirelint/packs/stripe@sha256:...
```

Pack protocol and local loading must be stable before remote distribution is introduced.

## 9. Go runtime support policy

Minimum supported Go: **1.25**.

CI must test Go 1.25 and 1.26 while both are supported release lines. Release binaries should be built with the newest supported stable line unless reproducibility/security requirements dictate otherwise.

Go remains an implementation detail of the primary binary. Provider-pack authors do not need Go.

## 10. Dependency budget

Phase A intentionally permits three runtime dependencies because each replaces a substantial standards implementation:

```text
github.com/google/cel-go                  v0.30.0
github.com/santhosh-tekuri/jsonschema/v6 v6.0.2
github.com/goccy/go-yaml                 v1.19.2
```

No CLI framework, HTTP framework, DI container, logging framework or plugin framework is justified yet. The Go standard library remains sufficient for those concerns.

## 11. Review trigger

Revisit this ADR when any of the following becomes true:

- CEL publishes a release whose declared Go module path changes from `github.com/google/cel-go`;
- official `go.yaml.in/yaml/v4` publishes a stable release;
- a real provider cannot be expressed with JSON Schema + CEL + trusted signature primitives;
- community pack distribution is implemented;
- a standardized query requirement makes RFC 9535 JSONPath necessary;
- executable third-party extensions become unavoidable.
