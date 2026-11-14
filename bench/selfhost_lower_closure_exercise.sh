#!/usr/bin/env bash
# Compare closure behavior through hosted and typed native compilation.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
IYI="${IYI:-$REPO/bin/iyi}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
. "$REPO/bench/lib/mutation.sh"
export IYI_PATH="$REPO/src"

build_compiler() {
  "$IYI" build -o "$WORK/stage1" src/compiler/tools/compile_native.iyi > "$WORK/build.log" 2>&1
}
check_fixture() {
  local fixture="$1"
  "$WORK/stage1" "bench/fixtures/$fixture.iyi" -o "$WORK/native" --pipeline typed --prelude > "$WORK/native.log" 2>&1 || return 1
  codesign -v --strict "$WORK/native" || return 1
  "$WORK/native" > "$WORK/native.out" 2>&1
  local result=$?
  [ "$result" -eq 0 ] && cmp -s "$WORK/host.out" "$WORK/native.out"
}
check_mutant() {
  local fixture="$1"
  if ! build_compiler; then
    echo 'INVALID: mutated compiler failed to build'
    return 0
  fi
  check_fixture "$fixture"
}

build_compiler || { cat "$WORK/build.log"; exit 1; }
status=0
for fixture in lower_closure_top_level lower_closure_nested_block; do
  "$IYI" build --prelude empty -o "$WORK/host" "bench/fixtures/$fixture.iyi" > "$WORK/host.build.log" 2>&1 || { cat "$WORK/host.build.log"; exit 1; }
  "$WORK/host" > "$WORK/host.out" 2>&1 || exit 1
  if check_fixture "$fixture"; then
    echo "$fixture: hosted and signed native exit 0 with identical output"
  else
    cat "$WORK/native.log"
    exit 1
  fi
done
prove_mutation 'program closure facts omitted' "$REPO/src/compiler/lower/lower.iyi" \
  'low.current_context.closure_facts = facts' 'low.current_context.closure_facts = nil' -- check_mutant lower_closure_top_level || status=1
prove_mutation 'yielded block loses closure context' "$REPO/src/compiler/lower/block.iyi" \
  'body.copy_closure_from(caller)' 'nil' -- check_mutant lower_closure_nested_block || status=1
exit "$status"
