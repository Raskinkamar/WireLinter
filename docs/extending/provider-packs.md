# Writing provider packs

A provider pack translates one documented integration surface into rules over a WireLinter Trace.

Before adding a pack, make sure the provider's wire behavior is documented well enough to make the checks precise. It is better to leave a property unclaimed than to encode an assumption as a rule.

## Choose the contract boundary

Start with the delivery surface, not the company name.

A good contract ID tells a reviewer which behavior is being checked. If two modes use different authentication or setup flows, split them.

Examples already in the repository include separate GitLab authentication modes and separate VTEX setup/delivery contracts.

## Pack layout

A typical pack looks like:

```text
packs/example-webhooks/
  pack.yaml
  rules/
    method.yaml
    signature.yaml
    ack-status.yaml
  signatures/
    request.yaml
```

A simple delivery-only contract may have only `pack.yaml` and CEL rules. A contract with a provider payload schema may also contain `schemas/`.

## `pack.yaml`

The manifest declares:

- Pack Protocol version;
- stable contract ID and display name;
- pack/documentation revision metadata;
- logical secrets;
- primary documentation references;
- rule and trusted-recipe files;
- optional metadata such as vendor, surface and region.

Keep documentation references specific enough that another contributor can find the exact behavior being asserted.

## Pick the least powerful mechanism

Use the simplest mechanism that can express the rule correctly:

1. JSON Schema for payload shape.
2. CEL for ordinary policy over captured evidence.
3. Trusted primitives when secret material or cryptographic verification must remain outside pack expressions.

Do not add provider-specific Go code because a rule is inconvenient to write. If the existing primitives cannot represent a real family of provider contracts safely, propose the reusable mechanism separately.

## Evidence-aware rules

When a rule cannot decide safely without specific evidence, use Pack Protocol evidence semantics instead of treating absence as a failure.

For CEL rules:

```text
when == false      -> notApplicable
requires == false  -> open
assert == true     -> pass
assert == false    -> fail
```

A required header can fail when the header capture is known to be complete. The same absent header should remain `open` when the capture is partial and absence cannot be proved.

## Authentication recipes

Trusted signature/secret/digest recipes operate on bounded inputs and compare values in trusted Go code.

If a provider signs exact raw request bytes, require exact raw-body fidelity. Do not reproduce the signature over decoded JSON.

If a vendor allows multiple algorithms or key modes and WireLinter only models one, make that limitation visible in the provider ID or metadata rather than silently falling back.

## Tests and fixtures

Authentication contracts should normally have deterministic fixtures that cover at least:

- the documented valid path;
- a wrong secret or signature;
- a missing secret when that should produce `open`;
- an altered raw body when the provider signs exact bytes.

Add provider-specific timing, header or acknowledgement fixtures when those rules are important to the contract.

Fixtures belong under `examples/traces/` when they are useful as canonical examples as well as tests.

## Validate locally

```bash
go build -o ./bin/wirelint ./cmd/wirelint

./bin/wirelint validate-pack --pack ./packs/<provider-id>
./bin/wirelint lint --pack ./packs/<provider-id> ./examples/traces/<fixture>.json
```

Then run the normal project checks:

```bash
go test ./...
go test -race ./...
go vet ./...
```

Bundled provider discovery is automatic for valid directories under `packs/`; do not add provider names to a Go switch or CI list.

## Review checklist

Before opening a pull request, verify that:

- the contract is scoped to a real provider surface;
- every behavioral claim is supported by primary documentation or an official SDK;
- no secret value appears in a Trace, report or CEL expression;
- raw-body signatures require exact fidelity;
- missing evidence produces `open` where absence cannot be proved;
- pass and failure behavior is covered by tests for non-trivial authentication;
- `validate-pack` succeeds.
