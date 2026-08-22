# ADR 0008 — Pack Protocol 1.1 implementation scope

Status: **Accepted**

Pack Protocol 1.1 is deliberately limited to trusted declarative signature verification.

It adds:

- named signature recipe files in the pack manifest;
- `signature` rule kind scoped to one Envelope;
- injected secret resolution;
- stable signature `messageId` outcomes;
- provider-controlled human message overrides;
- generic HMAC-SHA256 verification with exact evidence requirements;
- optional directional timestamp freshness.

It does **not** add active probes, replay scenarios, remote pack registries, Wasm, asymmetric signatures, arbitrary transforms, or framework SDK hooks.

Those features require separate evidence and trust models and must not be smuggled into 1.1 as convenience flags.
