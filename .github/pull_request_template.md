## Summary

<!-- What changed, and why? -->

## Evidence

<!-- For provider behavior: link the primary provider documentation or official SDK that defines the wire contract. For core changes: link the relevant issue/ADR or describe the reusable mechanism. -->

## Validation

- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] affected packs pass `validate-pack`

## Scope

- [ ] provider-specific policy stays in `packs/`
- [ ] core changes are provider-neutral
- [ ] no real secrets or sensitive webhook payloads were committed
- [ ] documentation was updated when public behavior changed
