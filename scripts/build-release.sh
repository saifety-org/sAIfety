#!/usr/bin/env bash
set -euo pipefail
export GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0
mkdir -p dist
version=${VERSION:-dev}
ldflags="-s -w -X github.com/saifety-org/sAIfety/internal/cli.Version=${version}"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
  os=${target%/*}
  arch=${target#*/}
  out="dist/saifety_${os}_${arch}"
  if [[ "$os" == windows ]]; then out="${out}.exe"; fi
  GOOS="$os" GOARCH="$arch" go build -ldflags "$ldflags" -o "$out" ./cmd/saifety
done

# Intentional compiler failure for CI gate acceptance check.
GOOS=linux GOARCH=amd64 go build ./ci-missing-build-target
