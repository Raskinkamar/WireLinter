# Result semantics

WireLinter separates a rule violation from missing evidence. This is part of the public behavior of the tool, not just presentation.

## `pass`

The rule applied, the required evidence was available, and the evidence satisfied the rule.

## `fail`

The rule applied, the required evidence was available, and the evidence violated the rule.

A failure may carry an error, warning or note level. Error-level failures affect the CLI exit code.

## `open`

The rule applies, but the current Trace cannot support a safe pass/fail decision.

Typical reasons include:

- the provider secret was not supplied to the trusted runtime;
- the capture did not contain a complete header set;
- exact raw-body evidence is unavailable for a byte-level signature;
- response evidence was not captured for an acknowledgement rule.

`open` is intentionally different from `pass`. WireLinter should not turn missing evidence into success.

## `notApplicable`

The rule is valid for the contract but does not apply to this particular delivery.

For evidence-aware CEL rules:

```text
when == false      -> notApplicable
requires == false  -> open
assert == true     -> pass
assert == false    -> fail
```

## Text and JSON reports

Text output is intended for terminal diagnosis. JSON output exposes the same report model for automation:

```bash
wirelint lint --provider github --format json ./trace.json
```

A report includes the provider/pack identity, Trace ID, rule results and summary counts.

## Exit status

The process exits with `1` when analysis completed and the report contains error-level failures. It exits with `2` when WireLinter could not perform the analysis correctly at all.

That distinction makes it possible for CI to tell an integration failure apart from a malformed Trace or broken pack.
