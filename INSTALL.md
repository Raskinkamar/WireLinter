# Installation

WireLinter is a standalone Go CLI. Published binaries do not require Node.js, Python, Java or Go on the target machine.

## Linux and macOS

```bash
curl -fsSL https://raw.githubusercontent.com/Raskinkamar/WireLinter/main/scripts/install.sh | sh
```

The installer detects the OS and architecture, downloads the matching GitHub Release archive, verifies it against `SHA256SUMS`, and installs `wirelint` to `~/.local/bin`. It does not use `sudo`.

Override the destination when needed:

```bash
curl -fsSL https://raw.githubusercontent.com/Raskinkamar/WireLinter/main/scripts/install.sh \
  | WIRELINT_INSTALL_DIR="$HOME/bin" sh
```

## Windows PowerShell

```powershell
irm https://raw.githubusercontent.com/Raskinkamar/WireLinter/main/scripts/install.ps1 | iex
```

The PowerShell installer verifies SHA-256, installs to `%LOCALAPPDATA%\WireLinter\bin`, and adds that directory to the user PATH when necessary. Open a new terminal after the first installation if the current shell does not resolve `wirelint`.

## Try it

```bash
wirelint version
wirelint demo
```

`demo` is offline and requires no credentials. It evaluates a bundled GitHub GraphQL exchange in which HTTP succeeds but the GraphQL response contains an error.

## Build from source

To build directly from the repository:

```bash
git clone https://github.com/Raskinkamar/WireLinter.git
cd WireLinter

go mod download
go build -o ./bin/wirelint ./cmd/wirelint

./bin/wirelint version
./bin/wirelint providers
```

For development, run the test suite before building:

```bash
go test ./...
go test -race ./...
go vet ./...
```

Go 1.25 and 1.26 are exercised in CI.

## Published binaries

Release builds are standalone archives for Linux, macOS and Windows on amd64 and arm64. A release also contains `SHA256SUMS` and GitHub artifact attestation metadata.

Version changes and releases are explicit maintainer decisions; normal feature work does not bump the project version.

### Verify an archive

Download the archive and `SHA256SUMS` from the same GitHub Release.

Linux:

```bash
grep " <archive-name>$" SHA256SUMS | sha256sum -c -
```

macOS:

```bash
grep " <archive-name>$" SHA256SUMS | shasum -a 256 -c -
```

Windows PowerShell:

```powershell
$Expected = ((Get-Content .\SHA256SUMS | Select-String " <archive-name>$").Line -split '\s+')[0].ToLower()
$Actual = (Get-FileHash ".\<archive-name>" -Algorithm SHA256).Hash.ToLower()
if ($Actual -ne $Expected) { throw "SHA-256 mismatch" }
```

With GitHub CLI installed:

```bash
gh attestation verify ./<archive-name> --repo Raskinkamar/WireLinter
```

The checksum verifies the bytes you downloaded. The attestation verifies the artifact's provenance; use both when provenance matters.

## Verify the installation

```bash
wirelint version
wirelint providers
```

To validate every contract embedded in the current binary:

```bash
while IFS= read -r provider; do
  wirelint validate-pack --provider "$provider"
done < <(wirelint providers)
```

Next: [Getting started](docs/getting-started.md).
