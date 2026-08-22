# Provider contracts

A WireLinter provider ID identifies a concrete protocol contract rather than an entire vendor integration.

## Discover bundled contracts

The binary is the catalog source of truth:

```bash
wirelint providers
```

Regional metadata can be used as a discovery filter:

```bash
wirelint providers --region BR
```

This keeps the catalog directory-driven: adding a valid bundled pack does not require a hardcoded provider list in the CLI, CI or release workflow.

## Contract scope

A vendor can have more than one provider ID when its surfaces differ materially.

Examples of differences that justify separate contracts include:

- legacy token authentication versus a signed webhook scheme;
- setup/URL verification versus normal event delivery;
- HTTPS webhooks versus an event-bus transport;
- a compatibility signature algorithm versus the vendor's newer recommended mode.

This prevents a rule that is correct for one surface from being silently applied to another.

## Secrets

Packs declare logical secrets and the environment variable used by the CLI to resolve them. Secret values are not stored in the Trace or Report and are not made available to CEL rules.

When a verification secret is not available, the relevant trusted rule normally reports `open` rather than assuming a mismatch.

## Validate a bundled contract

```bash
wirelint validate-pack --provider <id>
```

For a local pack:

```bash
wirelint validate-pack --pack ./packs/<id>
```

Validation checks the pack against the public schemas and loader invariants.

## Source of truth

A provider rule must be backed by current primary provider documentation or an official SDK. The pack records documentation references and revisions so a later contributor can revisit the behavior when a provider changes its protocol.

Provider documentation can change independently of WireLinter. A contract should be updated when the wire behavior changes; it should not broaden its scope by guesswork.

## Where contracts live

Bundled contracts are under [`packs/`](../../packs/). Each directory contains a `pack.yaml` manifest and the schemas/rules/trusted recipes needed by that contract.

To add one, see [Writing provider packs](../extending/provider-packs.md).
