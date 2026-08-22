# ADR 0010 — Release provenance and reproducibility

## Status

Accepted.

## Context

WireLinter is distributed as standalone executables. A release therefore needs stronger guarantees than a source-only project: users should be able to verify what they downloaded, and the repository should be able to prove that release artifacts came from a specific reviewed commit.

Release creation is intentionally separate from ordinary development. Feature and fix work does not change the project version. A maintainer explicitly decides when a version should be cut and creates the release tag.

## Decision

### Release trigger

The release workflow is triggered **only by a SemVer tag** matching `v*`.

There is no `release/v*` branch convention and no release request branch. Ordinary development stays on the normal Git workflow; versioning is a separate maintainer action.

The workflow validates that:

1. the ref is a tag;
2. the tag is valid SemVer;
3. the tag resolves to the exact workflow commit SHA.

### Build matrix

Release archives are built with the pinned supported Go toolchain for:

```text
linux/amd64
linux/arm64
darwin/amd64
darwin/arm64
windows/amd64
windows/arm64
```

`CGO_ENABLED=0`, `-trimpath`, deterministic archive ordering/timestamps, and explicit version injection are used by `scripts/release/build.sh`.

### Reproducibility gate

Normal CI builds the complete release archive matrix twice from the same source and toolchain and requires the resulting `SHA256SUMS` manifests to be identical.

Release output directories live outside the checkout during this proof so build artifacts cannot change repository dirty-state metadata between targets.

Automatic Go VCS stamping is disabled for release artifacts. Source identity is instead represented by the validated Git tag/commit and GitHub artifact attestation. This avoids making binary content depend on transient worktree state.

### Packaged-binary smoke test

CI and release workflows unpack the final Linux amd64 archive and exercise the real standalone executable against bundled provider packs. This catches failures that source-level tests alone cannot detect, including missing embedded packs or packaging mistakes.

### Integrity and provenance

Every release contains `SHA256SUMS`. The workflow verifies those checksums before publication and creates a GitHub artifact attestation for the released subjects.

The GitHub Release is created only after tests, race detection, vet/tidy checks, build, packaged-binary smoke testing, checksum verification, and attestation succeed.

## Consequences

- Normal feature work never needs a release branch.
- Version bumps happen only when a maintainer explicitly requests them.
- A release tag identifies both the source commit and the artifacts produced from it.
- The release path has no dependency on GoReleaser or another third-party release framework.
- Reproducibility failures block release packaging instead of being ignored.

## Verification

Development CI:

```text
go test ./...
go test -race ./...
go vet ./...
release matrix build A
release matrix build B
SHA256SUMS(A) == SHA256SUMS(B)
packaged-binary smoke
```

Release:

```text
SemVer tag
 -> validate tag/SHA
 -> tests
 -> race detector
 -> vet/tidy
 -> six cross-builds
 -> packaged-binary smoke
 -> SHA-256 verification
 -> GitHub artifact attestation
 -> GitHub Release
```
