#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/xray"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

exec docker compose -f "$ROOT_DIR/tui/compose.yml" run --rm xray-tui "$@"
