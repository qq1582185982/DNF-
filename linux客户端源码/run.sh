#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${1:-$SCRIPT_DIR/dnf-linux-client.conf}"

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Config not found: $CONFIG_PATH" >&2
  echo "Copy dnf-linux-client.conf.example to dnf-linux-client.conf and edit it." >&2
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  exec "$SCRIPT_DIR/dnf-linux-client" --config "$CONFIG_PATH"
fi

if command -v sudo >/dev/null 2>&1; then
  exec sudo "$SCRIPT_DIR/dnf-linux-client" --config "$CONFIG_PATH"
fi

echo "Root privileges are required. Re-run as root or install sudo." >&2
exit 1
