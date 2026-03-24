#!/usr/bin/env bash
set -euo pipefail

# Sherlock web server entrypoint.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${PORT:-3000}"
export PORT

WEB_BIN="bin/web"
if [[ ! -f "$WEB_BIN" ]] || find cmd internal web -name "*.go" -newer "$WEB_BIN" 2>/dev/null | head -1 | grep -q .; then
  mkdir -p bin
  go build -o "$WEB_BIN" ./cmd/web
fi

exec "$WEB_BIN" -port "$PORT"
