#!/bin/sh
set -eu

repo=b1ts23/xray-easy-cascade
case "$(uname -s)" in
  Linux) platform=linux ;;
  Darwin) platform=darwin ;;
  *) echo "Unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) architecture=amd64 ;;
  arm64|aarch64) architecture=arm64 ;;
  *) echo "Unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
esac

asset="vpnctl_${platform}_${architecture}"
base="https://github.com/${repo}/releases/latest/download"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/xray-easy-cascade.XXXXXX")
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT INT TERM

echo "Downloading the versioned release asset for ${platform}/${architecture}..."
curl --fail --location --silent --show-error "$base/$asset" -o "$tmp_dir/$asset"
curl --fail --location --silent --show-error "$base/$asset.sha256" -o "$tmp_dir/$asset.sha256"

expected=$(awk '{print $1}' "$tmp_dir/$asset.sha256")
if ! printf '%s\n' "$expected" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  echo "Release checksum file is invalid." >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp_dir/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')
else
  echo "A SHA-256 tool (sha256sum or shasum) is required." >&2
  exit 1
fi
if [ "$actual" != "$expected" ]; then
  echo "Release checksum mismatch; refusing to execute the download." >&2
  exit 1
fi

install_dir=${XDG_BIN_HOME:-"$HOME/.local/bin"}
mkdir -p "$install_dir"
chmod 700 "$install_dir"
install -m 0755 "$tmp_dir/$asset" "$install_dir/vpnctl"
echo "Installed controller: $install_dir/vpnctl"
exec "$install_dir/vpnctl" install "$@"
