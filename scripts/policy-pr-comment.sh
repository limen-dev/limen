#!/usr/bin/env bash
# Post (or update) one comment on a pull request with the effective-access
# diff from `limen policy diff --format markdown` (ADR-0028).
#
#   GH_TOKEN=... PR=123 scripts/policy-pr-comment.sh diff.md
#
# Needs the GitHub CLI. One comment per pull request, found by its marker, so
# pushing again updates it instead of adding another.
set -euo pipefail

body_file="${1:?usage: policy-pr-comment.sh <markdown file>}"
pr="${PR:?set PR to the pull request number}"
marker='<!-- limen-policy-diff -->'

body="$(printf '%s\n%s\n' "$marker" "$(cat "$body_file")")"
existing="$(gh api "repos/{owner}/{repo}/issues/${pr}/comments" --paginate \
  --jq "[.[] | select(.body | contains(\"${marker}\"))][0].id // empty")"

if [ -n "$existing" ]; then
  gh api -X PATCH "repos/{owner}/{repo}/issues/comments/${existing}" -f body="$body" >/dev/null
else
  gh api -X POST "repos/{owner}/{repo}/issues/${pr}/comments" -f body="$body" >/dev/null
fi
