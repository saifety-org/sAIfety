#!/usr/bin/env bash
set -euo pipefail
unformatted=$(git ls-files -z -- '*.go' | xargs -0 gofmt -l)
if [[ -n "$unformatted" ]]; then
  printf 'Run gofmt on:\n%s\n' "$unformatted" >&2
  exit 1
fi
