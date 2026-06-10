#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BIN_DIR="target/release"
WIN_DIR="target/x86_64-pc-windows-gnu/release"

# ── Linux build ─────────────────────────────────────────────────────────────
echo "=== Building Linux (x86_64-unknown-linux-gnu) ==="
cargo build --release
echo "Linux binary: $BIN_DIR/p2pchat"

# ── Windows cross-compile ────────────────────────────────────────────────────
echo ""
echo "=== Building Windows (x86_64-pc-windows-gnu) ==="
cargo build --release --target x86_64-pc-windows-gnu
echo "Windows binary: $WIN_DIR/p2pchat.exe"

# ── Bundle MinGW DLLs next to the exe ────────────────────────────────────────
echo ""
echo "=== Bundling MinGW runtime DLLs ==="
MINGW_SYSROOT="/usr/x86_64-w64-mingw32/bin"
for dll in libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll; do
    src="$MINGW_SYSROOT/$dll"
    if [[ -f "$src" ]]; then
        cp -v "$src" "$WIN_DIR/$dll"
    else
        echo "  WARNING: $dll not found at $src"
    fi
done

# ── Create NSIS installer (if available) ─────────────────────────────────────
echo ""
if command -v makensis &>/dev/null; then
    echo "=== Creating Windows installer ==="
    makensis -NOCD scripts/p2pchat.nsi
    mv -v p2pchat-setup-*.exe target/
    echo "Installer: target/p2pchat-setup-*.exe"
else
    echo "=== NSIS not installed — skipping installer ==="
    echo "Install it:  sudo pacman -S nsis"
    echo "Then run:    makensis scripts/p2pchat.nsi"
fi

echo ""
echo "=== Build complete ==="
echo "  Linux:   $BIN_DIR/p2pchat"
echo "  Windows: $WIN_DIR/p2pchat.exe"
