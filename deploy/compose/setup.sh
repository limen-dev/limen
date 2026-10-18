#!/usr/bin/env bash
# Interactive setup for the Limen dev stack. Checks what you need is installed,
# asks what to enable, starts it, and prints every port and how it is connected.
#
#   deploy/compose/setup.sh                       # asks
#   deploy/compose/setup.sh --yes                 # Limen + every stack, no questions
#   deploy/compose/setup.sh --yes --scale --stacks ssh,redis
#   deploy/compose/setup.sh --check               # only check the prerequisites
#
# It is a front end for stack.sh (which you can also call directly).
# Development only: static tokens, Dex static passwords, file-backed CA keys.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=stack-lib.sh
source "$here/stack-lib.sh"

yes=false want_scale=false check=false picked=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) yes=true ;;
    --scale) want_scale=true ;;
    --check) check=true ;;
    --stacks) picked="${2:?--stacks needs a comma-separated list}"; shift ;;
    -h|--help) sed -n 2,10p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ask() { # ask "question" default(y|n) -> 0 for yes
  local q="$1" def="$2" hint reply
  [ "$def" = y ] && hint="Y/n" || hint="y/N"
  $yes && { [ "$def" = y ]; return; }
  read -r -p "$q [$hint] " reply || reply=""
  reply="${reply:-$def}"
  case "$reply" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

stacks=()
if [ -n "$picked" ]; then
  IFS=, read -r -a stacks <<<"$picked"
elif $yes || [ ! -t 0 ]; then
  stacks=("${STACK_NAMES[@]}")
  [ -t 0 ] || echo "(no terminal: enabling everything; pass --stacks to choose)"
else
  bold "Limen"
  echo "  Always on: Postgres (state), S3 (audit batches and recordings), Dex (login),"
  echo "  the control plane, a proxy and a worker."
  ask "  Scale it (3 control planes, 3 proxies, 3 workers)?" n && want_scale=true
  echo
  bold "What should it connect to, and report to?"
  for s in "${STACK_NAMES[@]}"; do
    ask "  $(printf '%-14s' "$s") $(stack_describe "$s")" y && stacks+=("$s")
  done
fi

scale_flag=()
$want_scale && scale_flag=(--scale)

echo
bold "Checking prerequisites"
export LIMEN_PREFLIGHT_DONE=1
if ! stack_preflight ${scale_flag[@]+"${scale_flag[@]}"} ${stacks[@]+"${stacks[@]}"}; then
  echo
  echo "Fix the items marked MISSING or BUSY above and run this again." >&2
  exit 1
fi
$check && exit 0

echo
bold "Starting Limen$($want_scale && echo ' (scaled)') with: ${stacks[*]:-no extra stacks}"
echo "The first run builds the images and the CLI, which takes several minutes."
if ! $yes && [ -t 0 ]; then ask "Go?" y || { echo "Cancelled."; exit 0; }; fi
exec "$here/stack.sh" ${scale_flag[@]+"${scale_flag[@]}"} up "${stacks[@]:-none}"
