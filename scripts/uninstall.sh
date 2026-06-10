#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="p2pchat"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
DESKTOP_DIR="${DESKTOP_DIR:-/usr/share/applications}"
ICON_DIR="${ICON_DIR:-/usr/share/icons/hicolor/256x256/apps}"

echo "Uninstalling $BINARY_NAME"

sudo rm -f "$INSTALL_DIR/$BINARY_NAME"
sudo rm -f "$DESKTOP_DIR/p2pchat.desktop"
sudo rm -f "$ICON_DIR/p2pchat.png"

echo "Uninstallation complete."