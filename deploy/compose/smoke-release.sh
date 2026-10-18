#!/usr/bin/env bash
# Smoke-test a published Limen release: verify the checksums, run the CLI from
# the tarball, pull the published images by digest, and run the Phase 3.5 demo
# against them. This is the check ADR-0024 asks for before a pre-release becomes
# a release.
#
#   deploy/compose/smoke-release.sh v0.1.0-rc.1            # download with gh, then test
#   deploy/compose/smoke-release.sh v0.1.0-rc.1 --dir DIR  # assets are already in DIR
#
# Needs: gh (signed in, unless --dir), docker (signed in to ghcr.io for a private
# repository: `gh auth token | docker login ghcr.io -u <user> --password-stdin`),
# tar, and a checksum tool. The dev-only helper images (a fake Datadog and a
# test sshd) are built locally, because they are not part of a release.
set -euo pipefail

tag="${1:?usage: smoke-release.sh <tag> [--dir DIR] [--repo OWNER/REPO]}"
shift
dir=""
repo="${GITHUB_REPOSITORY:-jfcmartins/limen}"
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) dir="${2:?--dir needs a path}"; shift 2 ;;
    --repo) repo="${2:?--repo needs OWNER/REPO}"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/deploy/compose"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }
for tool in docker tar; do command -v "$tool" >/dev/null || fail "$tool is required"; done
if command -v sha256sum >/dev/null; then sums() { sha256sum -c "$@"; }
elif command -v shasum >/dev/null; then sums() { shasum -a 256 -c "$@"; }
else fail "sha256sum or shasum is required"; fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
if [ -z "$dir" ]; then
  command -v gh >/dev/null || fail "gh is required to download the release (or pass --dir)"
  step "Download $tag from $repo"
  dir="$work/assets"
  mkdir -p "$dir"
  gh release download "$tag" --repo "$repo" --dir "$dir" \
    || fail "could not download $tag (a draft release can't be fetched by tag: download its assets and use --dir)"
fi
[ -f "$dir/SHA256SUMS" ] || fail "no SHA256SUMS in $dir"

step "Checksums"
(cd "$dir" && sums SHA256SUMS) || fail "a file does not match SHA256SUMS"
pass "every asset matches SHA256SUMS"

step "The CLI from the tarball"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
  Linux-aarch64|Linux-arm64) target=aarch64-unknown-linux-gnu ;;
  Darwin-arm64) target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  *) fail "no release build for $(uname -s) $(uname -m)" ;;
esac
tar -C "$work" -xzf "$dir/limen-$tag-$target.tar.gz" || fail "missing limen-$tag-$target.tar.gz"
limen="$work/limen-$tag-$target/limen"
version="$("$limen" --version)"
case "$version" in *"${tag#v}"*) pass "limen reports $version" ;; *) fail "limen reports '$version', expected ${tag#v}" ;; esac
LIMEN_HOME="$work/home" "$limen" --help >/dev/null

step "The published images, pulled by digest"
[ -f "$dir/image-refs.txt" ] || fail "no image-refs.txt in $dir"
while read -r ref; do
  [ -n "$ref" ] || continue
  name="${ref##*/}"; name="${name%%@*}"   # limen-control-plane
  docker pull -q "$ref" >/dev/null || fail "could not pull $ref"
  reported="$(docker run --rm "$ref" --version)"
  case "$reported" in *"${tag#v}"*) ;; *) fail "$ref reports '$reported', expected ${tag#v}" ;; esac
  docker tag "$ref" "$name:dev"
  pass "$name ($ref)"
done < "$dir/image-refs.txt"

step "Helper images (built locally; not part of a release)"
source "$here/stack-lib.sh"
stack_setup ssh observability
"${compose[@]}" build fake-datadog sshd-target >/dev/null
pass "fake-datadog and sshd-target"

step "The Phase 3.5 demo, against the release"
LIMEN_RELEASE_IMAGES=1 LIMEN_BIN="$limen" "$here/demo-phase35.sh"
pass "release $tag passes the demo"
