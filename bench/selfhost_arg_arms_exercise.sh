#!/usr/bin/env bash
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
export IYI_PATH="$REPO/src"
IYI="${IYI_COMPILER:-$REPO/bin/iyi}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"

check_arms() {
  "$IYI" build -o "$WORK/probe" "$REPO/bench/selfhost_arg_arms_probe.iyi" > "$WORK/build.log" 2>&1 || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_union_overload.iyi" "$REPO/src" consume > "$WORK/union" || return 1
  printf '%s\n' 'arms=2 cover=true' 'main#consume:Int32' 'main#consume:String' > "$WORK/expected"
  cmp -s "$WORK/union" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_order.iyi" "$REPO/src" show > "$WORK/order" || return 1
  printf '%s\n' 'arms=2 cover=true' 'main#show:A' 'main#show:Node+' > "$WORK/expected"
  cmp -s "$WORK/order" "$WORK/expected"
}

check_arms || exit 1
status=0
prove_mutation 'cover requires a matching arm for each combination' "$REPO/src/compiler/semantic/cover.iyi" \
  '        return true if accepted' '        return false if accepted' -- check_arms || status=1
prove_mutation 'stricter overload is inserted before broader overload' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  'while at < ordered.size && !arm_more_specific?(definition, ordered[at], args, owner)' \
  'while at < ordered.size' -- check_arms || status=1
exit "$status"
