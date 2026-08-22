# ADR 0006 — Secret resolution boundary

Status: **Accepted for Pack Protocol 1.1 implementation**

Signature recipes refer to logical secret IDs. Provider packs never read environment variables, files, keychains, CI stores, or network secret managers directly.

## Decision

The signature runtime receives a `SecretResolver` interface from its caller:

```text
Lookup(secretRef) -> value | unavailable | execution error
```

The provider pack manifest may describe a conventional environment variable for CLI UX, but that mapping is not executed by the pack loader or rule engine.

This separation is required because:

- tests need deterministic in-memory secrets;
- future CLI installs must work across Node, Python, Go, Java, PHP, Ruby, .NET, and other application stacks;
- CI may inject secrets differently from local machines;
- a future keychain/Vault integration must not change Pack Protocol semantics;
- secret values and derived key material must never enter Trace or Report evidence.

## Result semantics

- secret reference exists in a valid pack, but no value is supplied by the resolver -> signature rule returns `open` / `secret-unavailable`;
- resolver itself fails -> execution error / CLI exit 2;
- supplied value violates the recipe's declared representation (for example invalid `whsec_` base64 material) -> execution/configuration error / CLI exit 2;
- a wrong but well-formed secret computes a non-matching MAC -> `fail` / `signature-mismatch`.

This distinction prevents local configuration failures from being mislabeled as provider/integration bugs.
