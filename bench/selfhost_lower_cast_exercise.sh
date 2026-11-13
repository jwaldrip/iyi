#!/usr/bin/env bash
# Fails when the typed lowering of stores into mixed unions (src/compiler/lower/cast.iyi)
# stops agreeing with the hosted code generator's module for the same fixture.
#
# For each fixture (bench/fixtures/lowcast_*.iyi) the hosted compiler builds the program
# against --prelude empty, with --emit llvm-ir and --no-debug. The module is normalised by the
# shared oracle awk (bench/lib/lower_oracle.sh), read through the port's IR text parser, and
# compared function by function with the port's lowering (bench/lib/lower_gate.iyi).
#
# A fixture the port lowers identically is built natively and run: its exit status must equal
# the hosted executable's. A fixture waiting on another slice is WAITING, and the reason is
# named in waiting_on below; it is counted, never silently passed.
#
# Mutation proofs patch the ported code, rebuild the driver, and require the check to fail on
# a fixture that the unmutated port lowers identically. While no fixture is identical, the
# mutations cannot be proven, and the gate fails and says so: it does not pass on nothing.
#
#   bash bench/selfhost_lower_cast_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
. "$REPO/bench/lib/mutation.sh"
. "$REPO/bench/lib/lower_oracle.sh"
WORK="$(mktemp -d)"

trap 'rm -rf "$WORK"' EXIT

echo "== 1. Building the port driver"
if ! "$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_lower_cast_exercise.iyi" > "$WORK/port.build.log" 2>&1; then
  echo "  the port driver does not build (see $WORK/port.build.log)"
  exit 1
fi
echo "  driver built"

# Fixtures waiting on another slice, by name (none now: the three cast fixtures are identical).
waiting_on() {
  case "$1" in
  esac
}

echo
echo "== 2. Each fixture: the hosted module against the port's lowering"
passed=0
e2e=""
diverged=0
waiting=0
for fixture in "$REPO"/bench/fixtures/lowcast_*.iyi; do
  name="$(basename "$fixture" .iyi)"
  if ! "$IYI" build --prelude empty --emit llvm-ir --no-debug -o "$WORK/$name" "$fixture" > "$WORK/$name.oracle.log" 2>&1 || [ ! -s "$WORK/$name.ll" ]; then
    echo "  $name: the hosted compiler did not emit its module (see $WORK/$name.oracle.log)"
    diverged=$((diverged + 1))
    continue
  fi
  awk "$CALL_TYPES" "$WORK/$name.ll" > "$WORK/$name.oracle.ll"

  if ! "$WORK/port" lower "$fixture" "$WORK/$name.oracle.ll" > "$WORK/$name.port.out" 2> "$WORK/$name.port.err"; then
    if [ -n "$(waiting_on "$name")" ]; then
      echo "  $name: WAITING, $(waiting_on "$name"): $(awk 'NR==1' "$WORK/$name.port.err")"
      waiting=$((waiting + 1))
      continue
    fi
    echo "  $name: REFUSED: $(awk 'NR==1' "$WORK/$name.port.err")"
    diverged=$((diverged + 1))
    continue
  fi
  echo "  $name:"
  awk '!/^SUMMARY/ { print "    " $0 }' "$WORK/$name.port.out"
  summary="$(awk '/^SUMMARY/ { print }' "$WORK/$name.port.out")"
  identical="$(echo "$summary" | awk '{ split($2, a, "="); print a[2] }')"
  total="$(echo "$summary" | awk '{ split($3, a, "="); print a[2] }')"
  if [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$identical" = "$total" ]; then
    if [ -n "$(waiting_on "$name")" ]; then
      echo "    $name: passes now: take it off waiting_on in this gate"
      diverged=$((diverged + 1))
    fi
    echo "    $name: PASSED, $identical of $total functions identical"
    passed=$((passed + 1))
    e2e="$e2e $name"
  elif [ -n "$(waiting_on "$name")" ]; then
    echo "    $name: WAITING, $(waiting_on "$name"): $identical of $total functions identical"
    waiting=$((waiting + 1))
  else
    echo "    $name: DIVERGED, $identical of $total functions identical"
    diverged=$((diverged + 1))
  fi
done
echo "  fixtures: $passed passed, $waiting waiting (named above), $diverged diverged or refused"
if [ "$diverged" -gt 0 ] || [ "$passed" -eq 0 ]; then
  status=1
fi

echo
echo "== 3. End to end: each fixture the port lowers identically, built natively and run"
e2e_pass=0
e2e_fail=0
if "$IYI" build -o "$WORK/compile_native" "$REPO/src/compiler/tools/compile_native.iyi" > "$WORK/tool.build.log" 2>&1; then
  for name in $e2e; do
    fixture="$REPO/bench/fixtures/$name.iyi"
    if ! "$IYI" build --prelude empty --no-debug -o "$WORK/$name.hosted" "$fixture" > "$WORK/$name.hosted.log" 2>&1; then
      echo "  $name: the hosted compiler cannot build it (see $WORK/$name.hosted.log)"
      e2e_fail=$((e2e_fail + 1))
      continue
    fi
    "$WORK/$name.hosted" > "$WORK/$name.hosted.out" 2>&1
    hs=$?
    if ! "$WORK/port" emit "$fixture" "$WORK/$name.oracle.ll" > "$WORK/$name.port.ll" 2> "$WORK/$name.emit.err"; then
      echo "  $name: the port writes no module: $(awk 'NR==1' "$WORK/$name.emit.err")"
      e2e_fail=$((e2e_fail + 1))
      continue
    fi
    if ! "$WORK/compile_native" "$WORK/$name.port.ll" -o "$WORK/$name.native" > "$WORK/$name.native.log" 2>&1; then
      echo "  $name: the native tool refuses it: $(awk 'NR==1' "$WORK/$name.native.log")"
      e2e_fail=$((e2e_fail + 1))
      continue
    fi
    "$WORK/$name.native" > "$WORK/$name.native.out" 2>&1
    ns=$?
    if [ "$ns" -eq "$hs" ] && cmp -s "$WORK/$name.hosted.out" "$WORK/$name.native.out"; then
      echo "  $name: native executable runs to the hosted result (status $hs, stdout identical)"
      e2e_pass=$((e2e_pass + 1))
    else
      echo "  $name: native status $ns, hosted $hs; stdout differs or status differs"
      e2e_fail=$((e2e_fail + 1))
    fi
  done
else
  echo "  the native tool does not build (see $WORK/tool.build.log)"
  e2e_fail=1
fi
echo "  end to end: $e2e_pass fixture(s) run to the hosted result, $e2e_fail failed"
if [ "$e2e_fail" -gt 0 ] || [ "$e2e_pass" -eq 0 ]; then
  status=1
fi

echo
echo "== 4. Mutation proofs: the gate must catch each patch to the ported code"
# The check rebuilds the driver from the patched source and requires the mixed-union fixture
# to be identical to the hosted module, which holds only when the store helpers are right.
cast_check() {
  "$IYI" build -o "$WORK/mut" "$REPO/bench/selfhost_lower_cast_exercise.iyi" > "$WORK/mut.build.log" 2>&1 || return 1
  "$WORK/mut" lower "$REPO/bench/fixtures/lowcast_mixed.iyi" "$WORK/lowcast_mixed.oracle.ll" > "$WORK/mut.out" 2> "$WORK/mut.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); exit !(a[2] == b[2] && a[2] > 0) }' "$WORK/mut.out" && return 0
  return 1
}
no_return_check() {
  "$IYI" build -o "$WORK/mut" "$REPO/bench/selfhost_lower_cast_exercise.iyi" > "$WORK/mut.build.log" 2>&1 || return 1
  "$WORK/mut" lower "$REPO/bench/fixtures/lowcast_noreturn_union.iyi" "$WORK/lowcast_noreturn_union.oracle.ll" > "$WORK/mut.out" 2> "$WORK/mut.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); exit !(a[2] == b[2] && a[2] > 0) }' "$WORK/mut.out"
}
struct_union_check() {
  "$IYI" build -o "$WORK/mut" "$REPO/bench/selfhost_lower_cast_exercise.iyi" > "$WORK/mut.build.log" 2>&1 || return 1
  : > "$WORK/struct_mutant_built"
  "$WORK/mut" lower "$REPO/bench/fixtures/lowcast_struct_union.iyi" "$WORK/lowcast_struct_union.oracle.ll" > "$WORK/mut.out" 2> "$WORK/mut.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); exit !(a[2] == b[2] && a[2] > 0) }' "$WORK/mut.out"
}
struct_union_check || { echo "  baseline: struct union fixture differs"; status=1; }
rm -f "$WORK/struct_mutant_built"
prove_mutation "a struct is refused from a mixed union" "$REPO/src/compiler/lower/cast.iyi" \
  '  if value_type.struct? && passed_by_value?(value_type)' '  if false' -- struct_union_check || status=1
if [ ! -f "$WORK/struct_mutant_built" ]; then
  echo "  NOT PROVEN: struct union mutant failed to build"
  status=1
fi
no_return_check || { echo "  baseline: no-return union fixture differs"; status=1; }
prove_mutation "a no-return union assignment stores a value" "$REPO/src/compiler/lower/cast.iyi" \
  '  return if at_terminator?(low) || TypeQueries.no_return?(value_type)' '  return if false' -- no_return_check || status=1
if [ "$passed" -eq 0 ]; then
  echo "  NOT PROVEN: no cast fixture is identical to the hosted module yet, so no mutation can be"
  echo "  shown to change the result. The three patches are listed in the gate's source; they run"
  echo "  as soon as lowcast_mixed (or another cast fixture) is identical."
  status=1
else
  prove_mutation "a true bool folds to zero" "$REPO/src/compiler/lower/cast.iyi" \
    "return low.builder.const_int(int_type, 1_i64)" "return low.builder.const_int(int_type, 0_i64)" -- cast_check || status=1
  prove_mutation "the value area is field zero" "$REPO/src/compiler/lower/cast.iyi" \
    "  index = low.builder.const_int(low.module.types.int32, 1_i64)" "  index = low.builder.const_int(low.module.types.int32, 0_i64)" -- cast_check || status=1
  prove_mutation "the type id load is not aligned" "$REPO/src/compiler/lower/cast.iyi" \
    "  load_aligned(low, low.module.types.int32, global.as(Global))" "  low.builder.load(low.module.types.int32, global.as(Global))" -- cast_check || status=1
fi

echo
if [ "$status" -eq 0 ]; then
  echo "== ALL CAST LOWERING CHECKS PASSED"
else
  echo "CAST LOWERING GATE FAILED"
fi
exit "$status"
