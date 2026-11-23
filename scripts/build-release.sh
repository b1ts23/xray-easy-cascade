#!/usr/bin/env bash
set -euo pipefail

version=${1:?usage: build-release.sh VERSION [OUTPUT_DIR]}
output_dir=${2:-dist}

mkdir -p "$output_dir"
: >"$output_dir/SHA256SUMS"

checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "A SHA-256 tool (sha256sum or shasum) is required." >&2
    exit 1
  fi
}

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${target%/*}
  arch=${target#*/}
  asset="vpnctl_${os}_${arch}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build \
    -trimpath \
    -ldflags="-s -w -X github.com/b1ts23/xray-easy-cascade/internal/command.Version=${version}" \
    -o "$output_dir/$asset" ./cmd/vpnctl
  digest=$(checksum "$output_dir/$asset")
  printf '%s  %s\n' "$digest" "$asset" >"$output_dir/$asset.sha256"
  printf '%s  %s\n' "$digest" "$asset" >>"$output_dir/SHA256SUMS"
done
