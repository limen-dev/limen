#!/usr/bin/env bash
# Regenerate docs/cli-reference.md from the clap command tree. CI fails when it is stale.
set -euo pipefail
cd "$(dirname "$0")/.."
UPDATE_CLI_REFERENCE=1 cargo test -p limen-cli --locked committed_reference_is_current
