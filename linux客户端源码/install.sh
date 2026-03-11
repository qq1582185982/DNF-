#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTANCE_NAME="${1:-vm95}"
CONFIG_DIR="/etc/dnf-linux-client"
CONFIG_PATH="$CONFIG_DIR/${INSTANCE_NAME}.conf"
SERVICE_PATH="/etc/systemd/system/dnf-linux-client@.service"
BIN_PATH="/usr/local/bin/dnf-linux-client"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Please run install.sh as root." >&2
  exit 1
fi

install -m 755 "$SCRIPT_DIR/dnf-linux-client" "$BIN_PATH"
install -d "$CONFIG_DIR"

if [[ ! -f "$CONFIG_PATH" ]]; then
  install -m 644 "$SCRIPT_DIR/dnf-linux-client.conf.example" "$CONFIG_PATH"
  echo "Created config template: $CONFIG_PATH"
else
  echo "Config already exists: $CONFIG_PATH"
fi

install -m 644 "$SCRIPT_DIR/dnf-linux-client@.service" "$SERVICE_PATH"
systemctl daemon-reload

echo
echo "Installed:"
echo "  binary:  $BIN_PATH"
echo "  config:  $CONFIG_PATH"
echo "  service: $SERVICE_PATH"
echo
echo "Next:"
echo "  1. Edit $CONFIG_PATH"
echo "  2. systemctl enable --now dnf-linux-client@${INSTANCE_NAME}"
