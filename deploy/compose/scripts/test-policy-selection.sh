#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
source "$here/lib.sh"
root="/repo with spaces"
repo_root="$(cd "$here/../../.." && pwd)"

assert_policy_paths() {
  local expected=("$root/examples/policy/shared") i kind
  for kind in "$@"; do
    expected+=("$root/examples/policy/stacks/$kind")
  done
  if [ "${#POLICY_FILES[@]}" -ne "${#expected[@]}" ]; then
    printf 'expected %s paths, got %s\n' "${#expected[@]}" "${#POLICY_FILES[@]}" >&2
    exit 1
  fi
  for ((i = 0; i < ${#expected[@]}; i++)); do
    if [ "${POLICY_FILES[$i]}" != "${expected[$i]}" ]; then
      printf 'path %s: expected %s, got %s\n' "$i" "${expected[$i]}" "${POLICY_FILES[$i]}" >&2
      exit 1
    fi
  done
}

stack_policy_files "$root"
assert_policy_paths
stack_policy_files "$root" tcp web
assert_policy_paths tcp web
stack_policy_files "$root" tcp tcp web
assert_policy_paths tcp web
stack_policy_files "$root" ssh db redis mongo search messaging bots kube observability
assert_policy_paths ssh database redis mongo search messaging bots kube

if stack_policy_files "$root" unknown 2>/dev/null; then
  echo "unknown stack was accepted" >&2
  exit 1
fi

stack_policy_files "$repo_root" "${STACK_NAMES[@]}"
for path in "${POLICY_FILES[@]}"; do
  if [ ! -d "$path" ]; then
    printf 'selected policy directory does not exist: %s\n' "$path" >&2
    exit 1
  fi
done

echo "stack policy selection passed"
