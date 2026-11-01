#!/usr/bin/env bash
# Which areas of CI a change touches. ci.yml runs only those; these are the rules the per-area
# workflows used to have as `paths:` filters. A check that starts reading a new file needs its
# pattern here (and a case in .github/scripts/test-ci-changes.sh).
#
#   .github/scripts/ci-changes.sh [<base>]   # files changed between <base> and HEAD; no base, or one that
#                                            # is not a commit (a new branch): every area
#   .github/scripts/ci-changes.sh --files    # the changed file names on stdin, one per line (tests)
#
# Prints rust=, audit=, infra=, workflows= and website= as true or false, ready for $GITHUB_OUTPUT.
# The secret scan has no entry: it always runs.
set -euo pipefail

# Everything except docs, the website, demos, assets, Terraform, dashboards and prose.
# (examples/ counts: the policy tests read it.)
is_rust() {
  case "$1" in
    .github/workflows/ci-rust.yml) return 0 ;;
    docs/*|website/*|demos/*|assets/*|deploy/terraform/*|deploy/grafana/*|*.md|LICENSE|.github/*) return 1 ;;
    *) return 0 ;;
  esac
}
# Manifests, the lock file and the deny config.
is_audit() {
  case "$1" in
    Cargo.toml|Cargo.lock|*/Cargo.toml|deny.toml|mise.toml|.github/workflows/audit.yml) return 0 ;;
    *) return 1 ;;
  esac
}
# Terraform, generated dashboards, dev users. crates/ counts: dashboards come from metric names.
is_infra() {
  case "$1" in
    deploy/terraform/*|deploy/grafana/*|deploy/compose/config/dev-users.toml|deploy/compose/scripts/gen-dev-users.py|crates/*|.github/workflows/ci-infra.yml) return 0 ;;
    *) return 1 ;;
  esac
}
is_workflows() {
  case "$1" in
    .github/workflows/*|.github/scripts/*) return 0 ;;
    *) return 1 ;;
  esac
}
# The build publishes docs/ and the compose README into the site.
is_website() {
  case "$1" in
    website/*|docs/*|deploy/compose/README.md|mise.toml|.github/workflows/ci-website.yml) return 0 ;;
    *) return 1 ;;
  esac
}
# A change to the entry point itself runs everything.
is_everything() {
  case "$1" in
    .github/workflows/ci.yml|.github/scripts/ci-changes.sh) return 0 ;;
    *) return 1 ;;
  esac
}

all() { printf 'rust=true\naudit=true\ninfra=true\nworkflows=true\nwebsite=true\n'; }

if [ "${1:-}" = "--files" ]; then
  files="$(cat)"
else
  base="${1:-}"
  if [ -z "$base" ] || ! git cat-file -e "${base}^{commit}" 2>/dev/null; then all; exit 0; fi
  files="$(git diff --name-only --no-renames "$base" HEAD)"
fi

rust=false audit=false infra=false workflows=false website=false
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if is_everything "$f"; then all; exit 0; fi
  if is_rust "$f"; then rust=true; fi
  if is_audit "$f"; then audit=true; fi
  if is_infra "$f"; then infra=true; fi
  if is_workflows "$f"; then workflows=true; fi
  if is_website "$f"; then website=true; fi
done <<< "$files"
printf 'rust=%s\naudit=%s\ninfra=%s\nworkflows=%s\nwebsite=%s\n' "$rust" "$audit" "$infra" "$workflows" "$website"
