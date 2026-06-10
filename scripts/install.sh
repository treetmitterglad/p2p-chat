#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="p2pchat"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
DESKTOP_DIR="${DESKTOP_DIR:-/usr/share/applications}"
ICON_DIR="${ICON_DIR:-/usr/share/icons/hicolor/256x256/apps}"

echo "Installing $BINARY_NAME to $INSTALL_DIR"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$REPO_ROOT/target/release/$BINARY_NAME" ]]; then
    echo "Binary not found. Building release..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
fi

sudo install -Dm755 "$REPO_ROOT/target/release/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"

echo "Installing desktop entry to $DESKTOP_DIR"
sudo install -Dm644 "$REPO_ROOT/scripts/p2pchat.desktop" "$DESKTOP_DIR/p2pchat.desktop"

if [[ -f "$REPO_ROOT/assets/icon.png" ]]; then
    echo "Installing icon to $ICON_DIR"
    sudo install -Dm644 "$REPO_ROOT/assets/icon.png" "$ICON_DIR/p2pchat.png"
fi

echo "Installation complete. Run '$BINARY_NAME' to start."