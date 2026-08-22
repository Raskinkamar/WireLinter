# Contributing to WireLinter

WireLinter has two kinds of changes, and keeping them separate is important:

- **provider policy** belongs in declarative packs under `packs/`;
- **reusable mechanisms** belong in the Go core.

A new provider should rarely require a new branch in Go code. A new core primitive should rarely exist for only one vendor.

## Before you start

For provider behavior, use primary provider documentation or an official SDK as the source of truth. Link the exact section in the pack. If two official sources disagree, record the difference instead of quietly choosing the behavior that is easiest to implement.

Do not infer signature formats, encodings, timeouts or retry behavior from blog posts or examples from unrelated SDKs.

## Adding a provider contract

Read [Writing provider packs](docs/extending/provider-packs.md) first.

The usual workflow is:

1. Identify the exact delivery or setup surface.
2. Confirm the wire contract in primary documentation.
3. Choose a concrete provider ID.
4. Add `packs/<provider-id>/pack.yaml` and its rules/recipes.
5. Add deterministic fixtures when the contract has non-trivial authentication or evidence behavior.
6. Test successful, failing and insufficient-evidence cases where they are meaningful.
7. Run `wirelint validate-pack --pack packs/<provider-id>`.
8. Confirm the bundled binary can discover the pack through `wirelint providers`.

Provider IDs describe protocol surfaces, not logos. If a vendor has two materially different authentication modes, model two contracts rather than hiding the distinction behind fallback logic.

## Changing the core

Start with [Development](docs/development.md) and the relevant ADRs under [`docs/architecture`](docs/architecture/README.md).

Core changes must be provider-neutral. Avoid code such as:

```go
if provider == "stripe" {
    // provider-specific behavior does not belong here
}
```

When several providers require the same mechanism, define the smallest reusable contract that can express the mechanism safely. Keep secret material inside trusted runtime boundaries; CEL and community packs must not gain arbitrary access to secrets, the filesystem or the network.

## Tests

Run the same baseline locally before opening a pull request:

```bash
go mod download
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/wirelint
```

If you changed a pack, also validate it directly:

```bash
./wirelint validate-pack --pack ./packs/<provider-id>
```

If you changed provider discovery or embedding, validate the bundled catalog from the built binary.

## Pull requests

Keep a pull request focused enough that a reviewer can answer three questions quickly:

- what behavior changed;
- which evidence or provider documentation justifies it;
- how the change is tested.

Do not mix an unrelated refactor into a provider addition. Do not bump the product version or create a release as part of ordinary feature work.

The pull request template includes a short checklist for provider and core changes.
