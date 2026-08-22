# Examples

`examples/traces/` contains canonical Trace fixtures used by documentation and tests.

Fixtures should be deterministic. Secrets included in examples are test values only and must never be copied into real integrations.

A useful provider fixture demonstrates behavior that is difficult to understand from a synthetic unit object alone: a signature vector, evidence-fidelity edge case, setup handshake or acknowledgement rule.

To lint a fixture:

```bash
wirelint lint --provider <provider-id> ./examples/traces/<file>.json
```

See [Getting started](../docs/getting-started.md) for a complete walkthrough.
