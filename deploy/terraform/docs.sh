#!/usr/bin/env bash
# Regenerates the reference section of every module's and example's README.md
# with terraform-docs (config: .terraform-docs.yml; version pinned in mise.toml).
#
#   mise exec -- deploy/terraform/docs.sh            write the READMEs
#   mise exec -- deploy/terraform/docs.sh --check    fail if any is out of date (CI)
#
# Run it through mise: another terraform-docs on your PATH can format the tables
# differently, and the check then fails in CI.
set -euo pipefail
cd "$(dirname "$0")"

args=()
[ "${1:-}" = "--check" ] && args+=(--output-check)

status=0
for dir in modules/*/ examples/complete examples/kubernetes; do
  [ -f "$dir/README.md" ] || { echo "missing $dir/README.md" >&2; status=1; continue; }
  terraform-docs --config .terraform-docs.yml ${args[@]+"${args[@]}"} "$dir" > /dev/null || status=1
done
exit "$status"
