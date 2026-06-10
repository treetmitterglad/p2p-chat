#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="p2pchat"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
DESKTOP_DIR="${DESKTOP_DIR:-/usr/share/applications}"
ICON_DIR="${ICON_DIR:-/usr/share/icons/hicolor/256x256/apps}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Installing $BINARY_NAME ==="

# ── Build ───────────────────────────────────────────────────────────────────
if [[ ! -f "$REPO_ROOT/target/release/$BINARY_NAME" ]]; then
    echo "Binary not found. Building release..."
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
fi

# ── Binary ──────────────────────────────────────────────────────────────────
echo "Installing binary to $INSTALL_DIR"
sudo install -Dm755 "$REPO_ROOT/target/release/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"

# ── Icon (SVG / scalable) ──────────────────────────────────────────────────
SVG_DEST=/usr/share/icons/hicolor/scalable/apps/$BINARY_NAME.svg
if [[ -f "$REPO_ROOT/assets/$BINARY_NAME.svg" ]]; then
    echo "Installing SVG icon to $SVG_DEST"
    sudo install -Dm644 "$REPO_ROOT/assets/$BINARY_NAME.svg" "$SVG_DEST"
else
    echo "Skipping SVG icon (assets/$BINARY_NAME.svg not found)"
fi

# ── Icon (PNG / 256×256) — optional ────────────────────────────────────────
PNG_DEST="$ICON_DIR/$BINARY_NAME.png"
if [[ -f "$REPO_ROOT/assets/$BINARY_NAME.png" ]]; then
    echo "Installing PNG icon to $PNG_DEST"
    sudo install -Dm644 "$REPO_ROOT/assets/$BINARY_NAME.png" "$PNG_DEST"
else
    echo "Skipping PNG icon (not present)"
fi

# ── Desktop entry ───────────────────────────────────────────────────────────
echo "Installing desktop entry to $DESKTOP_DIR"
sudo install -Dm644 "$REPO_ROOT/scripts/p2pchat.desktop" "$DESKTOP_DIR/p2pchat.desktop"

# ── Clean up stale / duplicate entries ──────────────────────────────────────
USER_LOCAL_DESKTOP="$HOME/.local/share/applications/p2pchat.desktop"
if [[ -f "$USER_LOCAL_DESKTOP" ]]; then
    echo "Removing stale user-local desktop entry: $USER_LOCAL_DESKTOP"
    rm -f "$USER_LOCAL_DESKTOP"
fi

# ── Refresh caches ──────────────────────────────────────────────────────────
echo "Updating icon cache..."
sudo gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true

echo "Updating desktop database..."
sudo update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

# ── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "Installation complete."
echo ""
echo "Run:  $BINARY_NAME          (GUI – with passphrase screen)"
echo "Run:  $BINARY_NAME init     (generate identity)"
echo "Run:  $BINARY_NAME chat --listen   (CLI chat, listen)"
echo "Run:  $BINARY_NAME chat <ticket>   (CLI chat, connect)"
echo "Or launch P2P Chat from your application menu."
