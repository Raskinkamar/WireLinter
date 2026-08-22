#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: scripts/release/build.sh <version> [output-dir]

Builds standalone WireLinter release archives for supported OS/architecture pairs.
The version must be SemVer without a leading v, for example 0.3.0 or 0.3.0-rc.1.
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 2
fi

version="$1"
out_dir_input="${2:-dist}"

semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
if [[ ! "$version" =~ $semver_re ]]; then
  printf 'release build: invalid SemVer %q\n' "$version" >&2
  exit 2
fi

for command in go git tar zip sha256sum install touch realpath; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'release build: required command %q is not available\n' "$command" >&2
    exit 2
  fi
done

repo_root="$(realpath -m "$(git rev-parse --show-toplevel)")"
cd "$repo_root"

case "$out_dir_input" in
  /*) out_dir="$(realpath -m "$out_dir_input")" ;;
  *) out_dir="$(realpath -m "$repo_root/$out_dir_input")" ;;
esac

case "$out_dir" in
  /|"$HOME"|"$repo_root"|"$repo_root/.git"|"$repo_root/.git/"*)
    printf 'release build: refusing unsafe output directory %q\n' "$out_dir" >&2
    exit 2
    ;;
esac

# Remove this invocation's output before checking source cleanliness. A release
# must not silently compile untracked .go/embed inputs or local modifications.
rm -rf "$out_dir"
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo 'release build: source checkout must be completely clean (including untracked files)' >&2
  exit 2
fi
mkdir -p "$out_dir"

source_date_epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  printf 'release build: invalid SOURCE_DATE_EPOCH %q\n' "$source_date_epoch" >&2
  exit 2
fi
export SOURCE_DATE_EPOCH="$source_date_epoch"

staging_root="$(mktemp -d)"
trap 'rm -rf "$staging_root"' EXIT

version_symbol='github.com/Raskinkamar/WireLinter/internal/cli.Version'
ldflags="-s -w -X ${version_symbol}=${version}"

targets=(
  'linux/amd64'
  'linux/arm64'
  'darwin/amd64'
  'darwin/arm64'
  'windows/amd64'
  'windows/arm64'
)

archives=()
for target in "${targets[@]}"; do
  IFS=/ read -r goos goarch <<<"$target"
  name="wirelint_${version}_${goos}_${goarch}"
  stage="$staging_root/$name"
  mkdir -p "$stage"

  binary='wirelint'
  if [[ "$goos" == 'windows' ]]; then
    binary='wirelint.exe'
  fi

  printf 'release build: %s/%s\n' "$goos" "$goarch"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build \
      -buildvcs=false \
      -trimpath \
      -ldflags "$ldflags" \
      -o "$stage/$binary" \
      ./cmd/wirelint

  chmod 0755 "$stage/$binary"
  install -m 0644 LICENSE "$stage/LICENSE"
  install -m 0644 README.md "$stage/README.md"

  # Normalize archive input timestamps so rerunning this build from the same
  # source/toolchain does not encode wall-clock time into release archives.
  touch -d "@${source_date_epoch}" "$stage/$binary" "$stage/LICENSE" "$stage/README.md"

  if [[ "$goos" == 'windows' ]]; then
    archive="$out_dir/${name}.zip"
    (
      cd "$stage"
      zip -X -q "$archive" "$binary" LICENSE README.md
    )
  else
    archive="$out_dir/${name}.tar.gz"
    tar \
      --sort=name \
      --mtime="@${source_date_epoch}" \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -C "$stage" \
      -czf "$archive" \
      "$binary" LICENSE README.md
  fi
  archives+=("$archive")
done

(
  cd "$out_dir"
  archive_names=()
  for archive in "${archives[@]}"; do
    archive_names+=("$(basename "$archive")")
  done
  LC_ALL=C printf '%s\n' "${archive_names[@]}" | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
  sha256sum -c SHA256SUMS
)

printf 'release build: wrote %d archives and SHA256SUMS to %s\n' "${#archives[@]}" "$out_dir"
