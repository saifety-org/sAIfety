#!/bin/sh
# sAIfety installer — downloads a prebuilt binary for your OS/arch and installs
# it to a directory on your PATH. No Go toolchain required.
#
#   curl -fsSL https://raw.githubusercontent.com/alexandr-mironov/saifety/main/scripts/install.sh | sh
#
# Overrides: SAIFETY_VERSION (tag, default: latest), PREFIX (install dir prefix).
set -eu

REPO="alexandr-mironov/saifety"
VERSION="${SAIFETY_VERSION:-latest}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac
case "$os" in
	linux | darwin) ;;
	*) echo "unsupported OS: $os (use 'go install' on this platform)" >&2; exit 1 ;;
esac

asset="saifety_${os}_${arch}"
if [ "$VERSION" = "latest" ]; then
	url="https://github.com/$REPO/releases/latest/download/$asset"
else
	url="https://github.com/$REPO/releases/download/$VERSION/$asset"
fi

# Pick an install dir that is on PATH and writable.
if [ -n "${PREFIX:-}" ]; then
	dir="$PREFIX/bin"
elif [ -w /usr/local/bin ] 2>/dev/null; then
	dir=/usr/local/bin
else
	dir="$HOME/.local/bin"
fi
mkdir -p "$dir"

tmp=$(mktemp)
echo "downloading $url"
curl -fSL --progress-bar -o "$tmp" "$url"
chmod +x "$tmp"
mv "$tmp" "$dir/saifety"
echo "installed $dir/saifety"

case ":$PATH:" in
	*":$dir:"*) ;;
	*) echo "note: $dir is not on your PATH; add it, e.g.:  export PATH=\"\$PATH:$dir\"" ;;
esac

echo "run: saifety --help"
