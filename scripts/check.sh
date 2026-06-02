#!/usr/bin/env bash
# Local pre-merge check: format, lint, test, license audit.
# Run from repo root: ./scripts/check.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== cargo fmt =="
cargo fmt --all -- --check

echo "== cargo clippy =="
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== cargo test =="
cargo test --workspace --all-features

echo "== cargo deny =="
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
else
    echo "cargo-deny not installed; skipping (install with: cargo install cargo-deny --locked)"
fi

echo "all checks passed"
