#!/usr/bin/env bash
# Verification gate: shell lint + Go vet/build/test.
set -euo pipefail
cd "$(dirname "$0")/.."
mapfile -t scripts < <(find . -name '*.sh' -not -path './.git/*')
shellcheck "${scripts[@]}"
if [ -f go.mod ]; then
  go vet ./...
  go build ./...
  go test ./...
fi
echo "proxy-agent verify OK"
