#!/usr/bin/env bash
set -euo pipefail

# Sherlock CLI entrypoint.
# Usage: ./cli.sh --block <blk.dat> <rev.dat> <xor.dat>

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ "${1:-}" != "--block" ]]; then
  printf '{"ok":false,"error":{"code":"INVALID_ARGS","message":"Usage: cli.sh --block <blk.dat> <rev.dat> <xor.dat>"}}\n'
  exit 1
fi

if [[ $# -ne 4 ]]; then
  printf '{"ok":false,"error":{"code":"INVALID_ARGS","message":"Block mode requires --block <blk.dat> <rev.dat> <xor.dat>"}}\n'
  exit 1
fi

for f in "$2" "$3" "$4"; do
  if [[ ! -f "$f" ]]; then
    printf '{"ok":false,"error":{"code":"FILE_NOT_FOUND","message":"File not found: %s"}}\n' "$f"
    exit 1
  fi
done

CLI_BIN="bin/cli"
if [[ ! -f "$CLI_BIN" ]] || find cmd internal -name "*.go" -newer "$CLI_BIN" 2>/dev/null | head -1 | grep -q .; then
  mkdir -p bin
  go build -o "$CLI_BIN" ./cmd/cli
fi

exec "$CLI_BIN" "$@"
