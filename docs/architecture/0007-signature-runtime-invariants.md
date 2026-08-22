# ADR 0007 — Signature runtime invariants

Status: **Accepted for Pack Protocol 1.1 implementation**

The signature runtime is intentionally smaller than a generic transformation engine.

## Invariants

1. No provider name is visible to the cryptographic evaluator.
2. Only HMAC-SHA256 is trusted in protocol 1.1.
3. Exact-body mechanisms require `bodyFidelity: exact`; decoded/re-serialized JSON is never substituted.
4. Semantic header lookup is case-insensitive, while query names and parsed signature field keys remain case-sensitive unless a future protocol revision explicitly introduces a justified transform.
5. Repeated singular headers are ambiguous, never silently reduced to first/last value.
6. Multiple signature candidates are supported for key rotation; one malformed candidate does not invalidate another valid candidate.
7. If every candidate is malformed, the rule fails with `malformed-signature`.
8. Missing evidence differs from proven absence. Partial header/query capture yields `open`, not `fail`.
9. Freshness is recipe-defined and directional. A provider may define only `maxAge`, only `maxFuture`, or both.
10. Offline freshness compares the signed timestamp to `Envelope.receivedAt`, never to the wall clock at lint time.
11. Secret values and HMAC key material are not emitted in errors, metadata, traces, or reports.
12. Parser input, field count, binding cardinality, and candidate count are bounded by trusted runtime constants.

These invariants are architecture tests. A future provider that cannot fit them should trigger a protocol-design review, not an `if provider == ...` escape hatch.
