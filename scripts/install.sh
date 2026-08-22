#!/bin/sh
set -eu

repo="${WIRELINT_REPOSITORY:-Raskinkamar/WireLinter}"
install_dir="${WIRELINT_INSTALL_DIR:-${HOME}/.local/bin}"
api_url="${WIRELINT_API_URL:-https://api.github.com/repos/${repo}}"
download_url="${WIRELINT_DOWNLOAD_URL:-https://github.com/${repo}/releases/download}"
module="${WIRELINT_MODULE:-github.com/${repo}}"

fail() {
  printf 'wirelint install: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

need uname
need mktemp
need curl
need sed
need awk
need tar
need install

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported operating system: $(uname -s)" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

install_from_source() {
  need go
  ref="${WIRELINT_SOURCE_REF:-main}"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT HUP INT TERM
  mkdir -p "$tmp/bin" "$install_dir"

  printf 'No published release found; building WireLinter from %s@%s...\n' "$module" "$ref"
  GOBIN="$tmp/bin" go install "${module}/cmd/wirelint@${ref}"
  [ -x "$tmp/bin/wirelint" ] || fail "source build completed without producing wirelint"
  install -m 0755 "$tmp/bin/wirelint" "$install_dir/wirelint"
}

version=""
if [ -n "${WIRELINT_VERSION:-}" ]; then
  version=${WIRELINT_VERSION#v}
else
  latest_json=$(curl -fsSL "${api_url}/releases/latest" 2>/dev/null || true)
  version=$(printf '%s' "$latest_json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | sed -n '1p')
fi

if [ -z "$version" ]; then
  install_from_source
else
  archive="wirelint_${version}_${os}_${arch}.tar.gz"
  base="${WIRELINT_RELEASE_BASE_URL:-${download_url}/v${version}}"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT HUP INT TERM

  printf 'Installing WireLinter %s for %s/%s...\n' "$version" "$os" "$arch"
  curl -fsSL "${base}/${archive}" -o "${tmp}/${archive}"
  curl -fsSL "${base}/SHA256SUMS" -o "${tmp}/SHA256SUMS"

  expected=$(sed -n "s/^\([0-9a-fA-F][0-9a-fA-F]*\)[[:space:]][[:space:]]*${archive}$/\1/p" "${tmp}/SHA256SUMS")
  [ -n "$expected" ] || fail "release checksum is missing for ${archive}"

  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "${tmp}/${archive}" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "${tmp}/${archive}" | awk '{print $1}')
  else
    fail "sha256sum or shasum is required to verify the download"
  fi
  [ "$actual" = "$expected" ] || fail "SHA-256 checksum mismatch"

  mkdir -p "$install_dir"
  tar -xzf "${tmp}/${archive}" -C "$tmp" wirelint
  install -m 0755 "${tmp}/wirelint" "${install_dir}/wirelint"
fi

installed_binary="${install_dir}/wirelint"
printf 'Installed %s\n' "$installed_binary"

# Verify the binary we just installed, never an older wirelint that happens to
# resolve earlier in PATH.
if [ "${WIRELINT_SKIP_RUN:-0}" != "1" ]; then
  "$installed_binary" version
fi

resolved=""
if command -v wirelint >/dev/null 2>&1; then
  resolved=$(command -v wirelint)
fi

if [ -z "$resolved" ]; then
  printf '\nAdd %s to PATH, then run:\n  wirelint demo\n' "$install_dir"
elif [ "$resolved" != "$installed_binary" ]; then
  printf '\nNote: your current PATH resolves wirelint to %s, not the binary just installed.\n' "$resolved"
  printf 'Run %s directly or put %s earlier in PATH.\n' "$installed_binary" "$install_dir"
else
  printf 'Try it: wirelint demo\n'
fi
