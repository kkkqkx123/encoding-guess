#!/usr/bin/env bash
# Publish the encoding-guess crate to crates.io.
#
# Usage:
#   ./publish.sh           # real publish
#   ./publish.sh --dry-run # cargo publish --dry-run
set -euo pipefail

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
fi

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Read the crate version; fall back to the workspace version for crates
# using `version.workspace = true`.
version=$(sed -n 's/^version *= *"\(.*\)".*/\1/p' "$CRATE_DIR/Cargo.toml" | head -1)
if [[ -z "$version" ]]; then
    ws_root="$CRATE_DIR"
    while [[ "$ws_root" != "/" && ! -f "$ws_root/Cargo.toml" ]]; do
        ws_root="$(dirname "$ws_root")"
    done
    version=$(sed -n 's/^version *= *"\(.*\)".*/\1/p' "$ws_root/Cargo.toml" | head -1)
fi
if [[ -z "$version" ]]; then
    echo "ERROR: could not determine crate version." >&2
    exit 1
fi

name=$(sed -n 's/^name *= *"\(.*\)".*/\1/p' "$CRATE_DIR/Cargo.toml" | head -1)

echo "=== Publishing $name v$version ==="

# Skip if this version is already on crates.io (User-Agent is required
# by the crates.io API).
if curl -sf -A "encoding-guess-publish-script" -o /dev/null "https://crates.io/api/v1/crates/$name/$version"; then
    echo "Skipping $name v$version: already published."
    exit 0
fi

cd "$CRATE_DIR"
if $DRY_RUN; then
    cargo publish --dry-run --allow-dirty --registry crates-io
else
    cargo publish --allow-dirty --registry crates-io
fi

echo "$name v$version published successfully."
