#!/usr/bin/env bash
# Post (or update) one comment on a pull request with the effective-access
# diff from `limen policy diff --format markdown` (ADR-0028).
#
#   GH_TOKEN=... PR=123 scripts/policy-pr-comment.sh diff.md
#
# Needs the GitHub CLI. One comment per pull request, found by its marker and
# its author, so pushing again updates it instead of adding another. Only a
# comment the token's own user wrote counts: anyone can paste the marker.
# COMMENT_AUTHOR is that login (default: github-actions[bot], the login of
# `github.token`).
set -euo pipefail

body_file="${1:?usage: policy-pr-comment.sh <markdown file>}"
pr="${PR:?set PR to the pull request number}"
author="${COMMENT_AUTHOR:-github-actions[bot]}"
marker='<!-- limen-policy-diff -->'

body="$(printf '%s\n%s\n' "$marker" "$(cat "$body_file")")"
# --paginate applies --jq to each page, so take the first id over all pages.
ids="$(gh api "repos/{owner}/{repo}/issues/${pr}/comments" --paginate \
  --jq ".[] | select(.user.login == \"${author}\" and (.body | contains(\"${marker}\"))) | .id")"
existing="${ids%%$'\n'*}"

if [ -n "$existing" ]; then
  gh api -X PATCH "repos/{owner}/{repo}/issues/comments/${existing}" -f body="$body" >/dev/null
else
  gh api -X POST "repos/{owner}/{repo}/issues/${pr}/comments" -f body="$body" >/dev/null
fi
