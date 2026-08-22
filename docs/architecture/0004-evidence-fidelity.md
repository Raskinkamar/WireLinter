# ADR 0004 — HTTP evidence fidelity and completeness

Status: **Accepted for architecture foundation**

WireLinter evaluates integration behavior from evidence captured through different acquisition modes: offline files, live probes, a future listener/proxy, CI fixtures, framework adapters, or imported logs. Those sources do not all preserve the same information.

A trustworthy diagnostic engine must therefore distinguish **what value it has**, **how faithfully it represents the original delivery**, and **whether an apparently absent value was actually observable**.

## 1. Do not call the canonical Trace wire-lossless

The Trace preserves exact bytes where the acquisition source can provide them, but it is not a universal packet capture format.

In particular:

- HTTP/2 requires lowercase field names on the wire;
- Go's `net/http.Header` is a semantic `map[string][]string` and canonicalizes names in common operations;
- proxies/frameworks may combine or transform fields;
- HTTP/2 and HTTP/3 do not have a textual HTTP/1 header block whose original bytes can be reconstructed from an application-level request object.

Therefore the canonical header list is **semantic HTTP evidence**, not a claim that field-name casing or global field order reproduces the original wire encoding.

Duplicate header values should be preserved when the acquisition source exposes them, because repeated values can be semantically relevant.

## 2. Body fidelity is explicit

Every canonical request/response records `bodyFidelity`:

```text
exact
reconstructed
unavailable
```

### `exact`

`rawBodyBase64` contains the exact entity/message body bytes observed before parsing or rewriting.

This is the required fidelity for checks whose protocol semantics sign or hash exact payload bytes.

### `reconstructed`

Bytes exist, but they were created from another representation after the original delivery, for example by serializing a parsed JSON object.

These bytes are useful for replay/structural inspection but MUST NOT be treated as the original signature input.

### `unavailable`

The raw bytes were not captured. `rawBodyBase64` is `null`.

A decoded representation MAY still exist.

## 3. Query fidelity is explicit

Every canonical request records `queryFidelity`:

```text
exact
reconstructed
unavailable
```

`rawQuery` is always present as a string; the fidelity field determines whether that string is an exact captured query component, reconstructed from decoded parameters, or merely empty because the source could not provide it.

This matters for providers that include query values or exact URL material in signature construction.

A rule that uses only a decoded query parameter may accept reconstructed query semantics if its mechanism explicitly permits that. A rule that signs the exact query string must require `exact`.

## 4. Headers are semantic evidence plus explicit completeness

Pack protocol does not treat the existing `headers` array as wire bytes. It is a semantic collection of HTTP field names and values.

Each request/response therefore records `headersCompleteness`:

```text
complete
partial
unavailable
```

### `complete`

The capture source asserts that the semantic header collection it exposes is complete. If a required header is absent, WireLinter may treat that absence as evidence.

### `partial`

Some header values were captured, but the acquisition source does not guarantee that all fields are present. A header that is present can still be used; a header that is missing cannot be assumed absent from the original delivery.

### `unavailable`

Headers were not captured. The canonical `headers` array must be empty.

This distinction is critical for imported logs. A log entry that omitted `Stripe-Signature` must not cause WireLinter to accuse the user's endpoint of receiving an unsigned Stripe delivery unless the importer can declare the header set complete.

A future acquisition mode that truly captures a protocol-specific raw field block must add a separate evidence artifact rather than silently upgrading the meaning of the semantic `headers` field.

## 5. Protocol version is evidence

Request/response may include the observed HTTP protocol version, for example:

```text
HTTP/1.1
HTTP/2.0
```

It is optional because imported/offline evidence may not know it, but active capture modes should record it when available.

## 6. Fidelity and completeness gate diagnostics

A rule must not evaluate a claim against evidence that is insufficient for that claim.

Future trusted primitives declare evidence requirements.

Examples:

```text
Stripe exact-body signature verification
requires: request.bodyFidelity == exact
```

```text
Required Stripe-Signature header is missing
can become fail only when: request.headersCompleteness == complete
```

If the body is reconstructed, or a missing header comes from a partial capture, WireLinter should produce an SARIF-style `open` result, not a failed-signature result.

If the relevant header is present in a partial capture, that value may still be evaluated because its presence is directly observed; completeness matters primarily when reasoning from absence.

This follows ADR 0003: insufficient evidence is different from both a provider violation and an execution error.

## 7. Relationship to WARC and HAR

WARC is a mature archival format capable of storing complete protocol records where available, and HAR represents browser-oriented HTTP transactions. Neither is adopted as WireLinter's canonical internal model:

- WARC is optimized for archival/interchange of retrieval records and is substantially broader/heavier than the rule-evaluation evidence graph WireLinter needs;
- HAR is oriented around browser performance/network export rather than integration rule provenance;
- neither directly models WireLinter Observations, rule evidence references, provider identity, scenario steps, result semantics, or evidence sufficiency.

Future import/export adapters MAY ingest compatible WARC/HAR evidence into a Trace. Importers must set fidelity/completeness based on what the source actually preserves.

## 8. Test requirements

The public Trace schema enforces core invariants:

- `exact` / `reconstructed` body fidelity requires base64 body bytes;
- `unavailable` body fidelity requires `rawBodyBase64: null`;
- `headersCompleteness: unavailable` requires an empty headers array.

Tests must include contradictory inputs to ensure these invariants cannot silently regress.
