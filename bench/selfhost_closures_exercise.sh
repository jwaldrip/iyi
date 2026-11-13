#!/usr/bin/env bash
# Compare lexical closure facts with the hosted compiler on the same fixture prelude.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
. "$REPO/bench/lib/mutation.sh"
export IYI_PATH="$REPO/bench/fixtures/semclos_prelude:$REPO/src"
export CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src"
ORACLE="$WORK/oracle"
PORT="$WORK/port"
FLOOR="$REPO/bench/selfhost_closures.floor"

printf '%s\n' '== 1. Building the oracle and closure facts driver'
if ! "$REPO/bin/crystal" build -Di_know_what_im_doing -o "$ORACLE" "$REPO/bench/selfhost_closure_oracle.cr" > "$WORK/oracle.log" 2>&1; then
  awk 'NR<=30' "$WORK/oracle.log"
  exit 1
fi
build_port() {
  "$REPO/bin/iyi" build -o "$PORT" "$REPO/bench/selfhost_closures_exercise.iyi" > "$WORK/port.log" 2>&1 || { awk 'NR<=30' "$WORK/port.log"; return 1; }
}
build_port || exit 1
if ! "$PORT" > "$WORK/self-check.log" 2>&1; then
  awk 'NR<=30' "$WORK/self-check.log"
  exit 1
fi

compare_fixtures() {
  local fixture rel expected count
  for fixture in bench/fixtures/semclos_*.iyi; do
    rel="$fixture"
    "$ORACLE" "$fixture" > "$WORK/oracle.out" 2> "$WORK/oracle.err" || { awk 'NR<=10' "$WORK/oracle.err"; return 1; }
    "$PORT" "$fixture" > "$WORK/port.out" 2> "$WORK/port.err" || { awk 'NR<=10' "$WORK/port.err"; return 1; }
    if ! diff -u "$WORK/oracle.out" "$WORK/port.out"; then
      printf 'DIFFERENT: %s\n' "$rel"
      return 1
    fi
    count=$(awk 'END {print NR+0}' "$WORK/oracle.out")
    expected=$(awk -v name="$rel" '$1 == name { print $2 }' "$FLOOR")
    if [ -z "$expected" ] || [ "$count" != "$expected" ] || [ "$count" -eq 0 ]; then
      printf 'FLOOR MISMATCH: %s %s expected %s\n' "$rel" "$count" "${expected:-missing}"
      return 1
    fi
    printf '  %s: %s identical frames\n' "$rel" "$count"
  done
}

printf '%s\n' '== 2. Comparing closure facts'
compare_fixtures || exit 1
mutation_check() {
  build_port && compare_fixtures
}

printf '%s\n' '== 3. Mutation proofs'
status=0
prove_mutation 'captured variable is omitted' "$REPO/src/compiler/semantic/closures.iyi" \
  'binding.captured = true' 'binding.captured = false' -- mutation_check || status=1
prove_mutation 'literal parameter does not shadow its outer variable' "$REPO/src/compiler/semantic/closures.iyi" \
  'frame.bindings << ClosureBinding.new(ClosureVar.new(arg.name, type))' 'nil' -- mutation_check || status=1
prove_mutation 'assignment does not declare a local' "$REPO/src/compiler/semantic/closures.iyi" \
  '@frame.bindings << ClosureBinding.new(ClosureVar.new(variable.name, type))' 'nil' -- mutation_check || status=1
if [ "$status" -ne 0 ]; then
  printf '%s\n' '== SOME CLOSURE CHECKS FAILED'
  exit 1
fi
printf '%s\n' '== ALL CLOSURE CHECKS PASSED'
