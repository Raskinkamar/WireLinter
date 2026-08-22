# Development

This page is for changes to WireLinter itself. If you only want to add a provider contract, start with [Writing provider packs](extending/provider-packs.md).

## Repository map

```text
cmd/wirelint/  CLI executable entrypoint
internal/cli/   command parsing and human/JSON output
internal/engine rule evaluation and report assembly
internal/listener local HTTP capture and forwarding
internal/model/ canonical Trace and Report models
internal/pack/  pack loading, validation and CEL compilation
internal/...    trusted signature/secret/digest runtimes
packs/          bundled provider policy
schemas/        public protocol schemas
examples/       canonical traces
scripts/        deterministic packaging/release helpers
docs/architecture/ ADRs and trust-boundary decisions
```

The directory structure is intentionally conventional for a Go CLI. Avoid moving packages only to make the tree look different; changes to package boundaries should have an architectural reason.

## Local checks

```bash
go mod download
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/wirelint
```

CI exercises Go 1.25 and 1.26 and also verifies deterministic packaging and the provider catalog from built binaries.

## Design boundary

The core owns mechanisms. Packs own provider policy.

Good core changes include a bounded parser or verification primitive needed by several contracts. Bad core changes include a `switch` on provider name or special casing a vendor inside the listener/engine.

Secret material must stay behind trusted runtime boundaries. Community pack data is not a code-execution plugin system: packs do not receive arbitrary Go, JavaScript or Python execution, filesystem access or network access.

## Trace fidelity

Several integrations sign exact bytes. Keep acquisition code careful about the distinction between raw evidence and reconstructed semantic content.

A change that normalizes a request body may be harmless for a JSON rule and fatal for a signature rule. Read the evidence-fidelity and signature ADRs before changing capture/normalization behavior.

## Pack Protocol changes

A protocol change is a compatibility decision, not just a schema edit.

When adding a new capability:

1. define the smallest provider-neutral behavior;
2. update the public schema and Go types together;
3. reject unsupported combinations defensively in the loader/runtime;
4. add unit tests independent of any provider;
5. add a provider consumer only after the primitive is proven;
6. document the trust and compatibility boundary in an ADR when the change is architectural.

Old protocol generations must not silently gain capabilities they did not declare.

## CLI changes

Keep commands scriptable. Human-friendly text is useful, but stable exit semantics and JSON output are part of the product surface.

New flags should have a clear default and should not weaken loopback or evidence-safety behavior implicitly.

## Release changes

Feature work does not automatically bump a version. Packaging and provenance are maintained separately; see [Installation](../INSTALL.md) and the release ADR.
