#!/usr/bin/env bash
set -euo pipefail

# Install dependencies, build binaries, and prepare fixture files.

go mod download
go mod tidy

mkdir -p bin out
go build -o bin/cli ./cmd/cli
go build -o bin/web ./cmd/web

for gz in fixtures/*.dat.gz; do
  if [[ -f "$gz" ]]; then
    dat="${gz%.gz}"
    if [[ ! -f "$dat" ]]; then
      echo "Decompressing $(basename "$gz")..."
      gunzip -k "$gz"
    fi
  fi
done

echo "Setup complete"
