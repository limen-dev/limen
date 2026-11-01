#!/usr/bin/env bash
# Checks scripts/ci-changes.sh against changes whose areas are known. Run by ci-workflows.yml.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fail=0

# expect "<files, one per line>" "<areas that must be true, space separated>"
expect() {
  local out want="$2" area
  out="$(printf '%s\n' "$1" | "$here/ci-changes.sh" --files)"
  for area in rust audit infra workflows website; do
    if printf '%s\n' "$out" | grep -qx "$area=true"; then got=true; else got=false; fi
    if [[ " $want " == *" $area "* ]]; then exp=true; else exp=false; fi
    if [ "$got" != "$exp" ]; then
      echo "FAIL: $(printf '%s' "$1" | tr '\n' ' ')-> $area=$got, want $exp" >&2
      fail=1
    fi
  done
}

expect "README.md" ""
expect "LICENSE" ""
expect "demos/demo-phase2.sh" ""
expect "assets/logo.svg" ""
expect "docs/guides/cli.md" "website"
expect "docs/design.md" "website"
expect "website/src/pages/index.astro" "website"
expect "deploy/compose/README.md" "website"
expect "crates/limen-core/src/lib.rs" "rust infra"
expect "crates/limen-worker/Cargo.toml" "rust infra audit"
expect "Cargo.lock" "rust audit"
expect "deny.toml" "rust audit"
expect "mise.toml" "rust audit website"
expect "proto/limen/manage/v1/manage.proto" "rust"
expect "examples/policy.yaml" "rust"
expect "scripts/check-versions.sh" "rust"
expect "deploy/compose/.env" "rust"
expect "deploy/compose/config/dev-users.toml" "rust infra"
expect "deploy/terraform/modules/audit/main.tf" "infra"
expect "deploy/grafana/generate.py" "infra"
expect ".github/workflows/ci-rust.yml" "rust workflows"
expect ".github/workflows/audit.yml" "audit workflows"
expect ".github/workflows/ci-website.yml" "website workflows"
expect ".github/workflows/release.yml" "workflows"
expect ".github/dependabot.yml" ""
expect ".github/CODEOWNERS" ""
expect ".gitleaksignore" "rust"
expect "docs/guides/cli.md
crates/limen-core/src/lib.rs" "rust infra website"
expect "" ""
# the entry point runs everything
expect ".github/workflows/ci.yml" "rust audit infra workflows website"
expect "scripts/ci-changes.sh" "rust audit infra workflows website"

# no base, or a base that is not a commit (a new branch): everything
for base in "" 0000000000000000000000000000000000000000; do
  out="$("$here/ci-changes.sh" $base)"
  [ "$(printf '%s\n' "$out" | grep -c '=true')" = 5 ] || { echo "FAIL: base '$base' did not run everything" >&2; fail=1; }
done

[ "$fail" = 0 ] && echo "ci-changes: all cases ok"
exit "$fail"
