#!/usr/bin/env bash
# Compare closure behavior through hosted and typed native compilation.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
IYI="${IYI:-$REPO/bin/iyi}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
. "$REPO/bench/lib/mutation.sh"
. "$REPO/bench/lib/lower_oracle.sh"
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

check_macro_ir() {
  local fixture=lower_macro_proc_locations
  "$IYI" build -o "$WORK/core" bench/selfhost_lower_core_exercise.iyi > "$WORK/core.log" 2>&1 || return 1
  "$IYI" build --prelude empty --emit llvm-ir --no-debug -o "$WORK/macro" "bench/fixtures/$fixture.iyi" > "$WORK/macro.log" 2>&1 || return 1
  awk "$CALL_TYPES" "$WORK/macro.ll" > "$WORK/macro.normalized.ll"
  "$WORK/core" lower "bench/fixtures/$fixture.iyi" "$WORK/macro.normalized.ll" > "$WORK/macro.out" 2>&1 || return 1
  grep -qx 'SUMMARY identical=6 total=6 module=1' "$WORK/macro.out"
}

check_macro_mutant() {
  if ! "$IYI" build -o "$WORK/core-mutant" bench/selfhost_lower_core_exercise.iyi > "$WORK/core-mutant.log" 2>&1; then
    echo 'INVALID: macro mutant driver failed to build'
    return 0
  fi
  if ! "$WORK/core-mutant" lower bench/fixtures/lower_macro_proc_locations.iyi "$WORK/macro.normalized.ll" > "$WORK/macro-mutant.out" 2>&1; then
    echo 'INVALID: macro mutant could not lower fixture'
    return 0
  fi
  grep -qx 'SUMMARY identical=6 total=6 module=1' "$WORK/macro-mutant.out"
}

check_mark() {
  "$WORK/stage1" bench/fixtures/closure_gc_marking.iyi -o "$WORK/mark" --pipeline typed --prelude > "$WORK/mark.build.log" 2>&1 || return 1
  codesign -v --strict "$WORK/mark" || return 1
  "$WORK/mark" > "$WORK/mark.out" 2>&1 || return 1
  grep -qx 'MARKING WHITE SHADED 42' "$WORK/mark.out"
}

# A missing or expired mark is invalid, not proof that a barrier mutation
# was caught. Only the explicitly observed white-but-unshaded state counts.
check_barrier_mutant() {
  if ! build_compiler || ! "$WORK/stage1" bench/fixtures/closure_gc_marking.iyi -o "$WORK/mark" --pipeline typed --prelude > "$WORK/mark.build.log" 2>&1 || ! codesign -v --strict "$WORK/mark"; then
    echo 'INVALID: barrier mutant did not build and sign'
    return 0
  fi
  "$WORK/mark" > "$WORK/mark.out" 2>&1
  local result=$?
  if [ "$result" -eq 1 ] && grep -qx 'MARKING WHITE UNSHADED' "$WORK/mark.out"; then
    return 1
  fi
  echo 'INVALID: barrier mutant did not produce a white unshaded object under an active mark'
  return 0
}


build_compiler || { cat "$WORK/build.log"; exit 1; }
status=0
for fixture in lower_closure_top_level lower_closure_nested_block lower_pointerof_arg lower_pointerof_proc_arg lower_macro_closure lower_macro_proc_locations; do
  "$IYI" build --prelude empty -o "$WORK/host" "bench/fixtures/$fixture.iyi" > "$WORK/host.build.log" 2>&1 || { cat "$WORK/host.build.log"; exit 1; }
  "$WORK/host" > "$WORK/host.out" 2>&1 || exit 1
  if check_fixture "$fixture"; then
    echo "$fixture: hosted and signed native exit 0 with identical output"
  else
    cat "$WORK/native.log"
    exit 1
  fi
done
check_macro_ir || { cat "$WORK/macro.out"; exit 1; }
"$IYI" build -o "$WORK/mark-host" bench/fixtures/closure_gc_marking.iyi > "$WORK/mark.host.log" 2>&1 || { cat "$WORK/mark.host.log"; exit 1; }
"$WORK/mark-host" > "$WORK/mark.host.out" 2>&1 || { cat "$WORK/mark.host.out"; exit 1; }
grep -qx 'MARKING WHITE SHADED 42' "$WORK/mark.host.out" || exit 1
check_mark || { cat "$WORK/mark.build.log" "$WORK/mark.out"; exit 1; }
echo 'hosted and native: marking active, object white before captured write and shaded after'
prove_mutation 'program closure facts omitted' "$REPO/src/compiler/lower/lower.iyi" \
  'low.current_context.closure_facts = facts' 'low.current_context.closure_facts = nil' -- check_mutant lower_closure_top_level || status=1
prove_mutation 'yielded block loses closure context' "$REPO/src/compiler/lower/block.iyi" \
  'body.copy_closure_from(caller)' 'nil' -- check_mutant lower_closure_nested_block || status=1
prove_mutation 'macro proc loses call-site location' "$REPO/src/compiler/lower/proc.iyi" \
  'place = low.current_context.macro_origin || node.location' 'place = node.location' -- check_macro_mutant || status=1
prove_mutation 'address-taken parameter is not spilled' "$REPO/src/compiler/lower/fun.iyi" \
  '@names.add(t.as(Var).name) if t.is_a?(Var)' 'nil' -- check_mutant lower_pointerof_arg || status=1
prove_mutation 'captured reference store lacks marking barrier' "$REPO/src/compiler/lower/cast.iyi" \
  'if low.analysed.program.types["IyiHeap"]?.nil? || !has_inner_pointers?(target) || stack_pointer?(pointer) || begin_fn.nil? || shade_fn.nil?' \
  'if true || low.analysed.program.types["IyiHeap"]?.nil? || !has_inner_pointers?(target) || stack_pointer?(pointer) || begin_fn.nil? || shade_fn.nil?' -- check_barrier_mutant || status=1
exit "$status"
