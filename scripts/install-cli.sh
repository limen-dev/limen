#!/usr/bin/env bash
# Build the limen CLI from this checkout and install it on your PATH.
#
#   scripts/install-cli.sh                 # installs to ~/.local/bin/limen
#   PREFIX=/usr/local scripts/install-cli.sh
#
# Re-run it after pulling to upgrade. Needs a Rust toolchain (rustup reads the
# version pinned in rust-toolchain.toml). Release tarballs (ADR-0024) will
# replace the source build once the repository is published.
set -euo pipefail

prefix="${PREFIX:-$HOME/.local}"
root="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found. Install Rust with rustup: https://rustup.rs" >&2
  exit 1
fi

cd "$root"
# --locked: build exactly the versions in Cargo.lock. --force: replace an earlier install.
cargo install --locked --force --path crates/limen-cli --root "$prefix"

bin="$prefix/bin/limen"
echo
echo "Installed $("$bin" --version 2>/dev/null || echo limen) to $bin"

case ":$PATH:" in
  *":$prefix/bin:"*) ;;
  *)
    echo "$prefix/bin is not on your PATH. Add this to your shell profile:"
    echo "  export PATH=\"$prefix/bin:\$PATH\""
    ;;
esac
