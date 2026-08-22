# ADR 0003 — Rule outcomes, execution failures, and CLI exit semantics

Status: **Accepted for architecture foundation**

WireLinter must distinguish a verified integration violation from insufficient evidence, a rule that does not apply, and its own inability to perform a trustworthy analysis. Mixing those states would make CI results misleading.

## 1. Exit-code contract

WireLinter follows the successful-analysis / violation / execution-failure model used by mature linters such as ESLint:

```text
0  analysis completed successfully and no configured failure threshold was exceeded
1  analysis completed successfully and failing rule results exceeded the configured threshold
2  analysis could not be completed reliably because of input, pack, configuration, evaluation, or internal failure
```

Default threshold behavior:

- `fail + error` causes exit 1;
- `fail + warning` is reported but does not cause exit 1 by default;
- `fail + note` does not cause exit 1;
- `open` and `notApplicable` do not cause exit 1 by themselves.

A later CLI/config layer may support a `maxWarnings`-style threshold.

## 2. Result kind follows SARIF semantics

SARIF already distinguishes whether a rule passed, failed, lacked enough evidence, or did not apply. WireLinter adopts the same conceptual split rather than inventing a conflicting taxonomy:

```text
pass           rule evaluated and no problem was found
fail           rule evaluated and a problem was proven
open           rule evaluated but available evidence is insufficient to decide
notApplicable  rule was not evaluated because it does not apply to this subject
```

For `fail`, the result level is:

```text
error | warning | note
```

For every other kind, level is `none`.

This separation matters. "We do not have the original raw body" is not a low-severity signature failure; it is an `open` result because the signature cannot be decided from the available evidence.

## 3. Failing results are claims about the integration

A `fail` result exists only when WireLinter successfully evaluated a valid rule against valid canonical evidence and proved the assertion was not satisfied.

Examples:

```text
valid JSON Schema rule evaluated payload; payload violates schema -> fail
valid CEL assertion evaluated to false                            -> fail
trusted signature mechanism evaluated sufficient evidence;
no candidate signature matched                                    -> fail
```

Every `fail` result must contain deterministic evidence references sufficient to explain what supported the claim.

## 4. `open` means evidence insufficiency, not runtime failure

An `open` result means the rule itself is valid and WireLinter executed correctly, but a property cannot be proven with the captured evidence.

Examples:

- an exact-body signature check receives `bodyFidelity: reconstructed`;
- a required header is absent but `headersCompleteness: partial`, so absence cannot be proven;
- duplicate requests were observed but no side-effect observer exists to determine whether the application duplicated a charge.

An `open` result should reference the evidence that explains the uncertainty, such as `/envelopes/0/request/bodyFidelity` or `/envelopes/0/request/headersCompleteness`.

## 5. Pack/input/runtime failures are not rule results

The following are execution failures and therefore CLI exit 2:

- provider pack manifest is invalid;
- rule schema is invalid;
- duplicate or incompatible rule IDs;
- referenced docs/schema/secret definitions do not exist;
- CEL expression cannot compile or exceeds configured compile limits;
- CEL evaluation returns an error or exceeds runtime cost limits;
- JSON Schema cannot compile;
- a rule's `targetPointer` is syntactically valid but does not resolve;
- canonical Trace/Envelope input does not validate against the WireLinter schema;
- evidence pointer declared by a failing/open result cannot be resolved;
- pack protocol version is incompatible;
- internal invariant fails.

These conditions mean WireLinter cannot honestly classify the integration as pass, fail, open, or notApplicable for that evaluation.

## 6. Missing JSON Pointer target is a pack/evaluation error

RFC 6901 defines pointer-resolution failure but deliberately leaves application-specific handling to the application.

WireLinter's policy is strict:

> A `targetPointer` that does not resolve is an evaluation error, not a provider failure.

If a provider rule intends to report that a field is absent, the rule must target a stable parent object and use JSON Schema `required` or an explicit CEL assertion.

```yaml
kind: json-schema
targetPointer: /request/decodedBody
schemaRef: event
```

Do not target `/request/decodedBody/id` and reinterpret pointer-not-found as a user violation. That would make a typo in the pack indistinguishable from a broken integration.

## 7. `when` controls applicability, not error recovery

For a rule with `when`:

1. evaluate `when`;
2. `false` -> `notApplicable`;
3. `true` -> evaluate the assertion;
4. CEL error -> execution failure, not `fail`;
5. assertion true -> `pass`;
6. assertion false -> `fail`.

Pack authors must not rely on runtime errors as control flow.

## 8. Result severity and rule stability are separate

`stability` describes compatibility maturity:

```text
stable | preview | deprecated
```

Rule severity describes the impact if that rule fails:

```text
error | warning | info
```

The engine maps those to SARIF-compatible result levels for `fail`:

```text
error   -> error
warning -> warning
info    -> note
```

For `pass`, `open`, and `notApplicable`, level is `none` regardless of configured rule severity.

## 9. Reports contain explicit outcomes

A successful run produces a report even when every rule passes. Machine consumers should not infer success from missing findings.

The report therefore carries `results[]` and summary counters for:

```text
pass
fail
open
notApplicable
errors
warnings
notes
```

Execution failures use the returned `error` / future structured CLI error envelope rather than fabricating a pseudo-rule result.

## 10. Engine boundary

The engine contract remains simple:

```text
Evaluate(trace, pack) -> (Report, error)

Report.Results -> trustworthy rule outcomes
error          -> pack/input/evaluation/internal failure
```

This boundary must remain consistent across `lint`, future `probe`, `listen`, `replay`, JSON output, SARIF conversion, and CI.
