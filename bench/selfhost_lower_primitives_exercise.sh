#!/usr/bin/env bash
# Fails when the typed lowering of primitives (src/compiler/lower/primitives.iyi) stops
# agreeing with the hosted code generator's module for the same fixture.
#
# For each fixture (bench/fixtures/lowprim_*.iyi) the hosted compiler builds the program
# against --prelude empty, with --emit llvm-ir and --no-debug. The builtin primitives are
# the library's own (src/primitives.cr), so a fixture calls them directly and declares
# none. Its module is read through the port's IR text parser and printed by the port's
# printer. The port analyses the fixture (the builtin stand-in,
# bench/lib/primitive_stand_in.iyi, declares the library's builtin operators until the
# semantic pass does), lowers it, and prints the module. The two normalised texts are
# compared function by function (bench/lib/lower_gate.iyi, shared with the other gates).
#
# Each fixture the port lowers identically is then built to a native executable by the
# native tool and run: its exit status and stdout must equal the hosted executable's.
#
# Mutation proofs patch the ported code, rebuild the driver, and require the check to
# fail. A patch that changes nothing is refused by prove_mutation.
#
#   bash bench/selfhost_lower_primitives_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
. "$REPO/bench/lib/mutation.sh"
. "$REPO/bench/lib/lower_oracle.sh"
WORK="$(mktemp -d)"

trap 'rm -rf "$WORK"' EXIT

echo "== 1. Building the port driver"
if ! "$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_lower_primitives_exercise.iyi" > "$WORK/port.build.log" 2>&1; then
  echo "the port driver failed to build:"
  awk '!/^ld: warning/ && NR<=20' "$WORK/port.build.log"
  exit 1
fi
echo "  driver built"

echo
echo "== 2. Each fixture: the hosted module against the port's lowering"
passed=0
e2e=""
diverged=0
waiting=0
# Fixtures that wait on a NEEDS.md row, by name. The port refuses them and the gate reports them
# WAITING, naming the row; a waiting fixture that starts to pass fails the gate until it is
# taken off this list, so a wait cannot outlive its cause unnoticed.
waiting_on() {
  case "$1" in
    lowprim_ptr) echo "the generic metaclass resolves its receiver now (S1c, 17bc4d2f8), but the bare analysis declares no Pointer primitives, so Pointer(Int32).malloc is undefined: the hosted oracle needs the prelude, and the bare dump has none (NEEDS.md row 19; the Pointer primitives are increment 2)" ;;
  esac
}

# Fixtures that lower with a known divergence, named, not yet fixed. The gate fails if one starts to match,
# so the list stays honest. None now.
known_divergence() {
  case "$1" in
  esac
}
# Fixtures identical to the hosted module whose native executable waits by name. None now: defs are emitted Iyi
# (fun.iyi), so the native tool builds lowprim_alloc_struct.
e2e_waiting_on() {
  case "$1" in
  esac
}
for fixture in "$REPO"/bench/fixtures/lowprim_*.iyi; do
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
    echo "    $name: PASSED, $identical of $total functions identical"
    passed=$((passed + 1))
    e2e="$e2e $name"
    if [ -n "$(waiting_on "$name")" ] || [ -n "$(known_divergence "$name")" ]; then
      echo "    $name: passes now: take it off the WAITING or KNOWN_DIVERGED list in this gate"
      diverged=$((diverged + 1))
    fi
  else
    if [ -n "$(known_divergence "$name")" ]; then
      echo "    $name: WAITING, known divergence: $identical of $total functions identical: $(known_divergence "$name")"
      waiting=$((waiting + 1))
    else
      echo "    $name: DIVERGED, $identical of $total functions identical"
      diverged=$((diverged + 1))
    fi
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
e2e_waiting=0
if "$IYI" build -o "$WORK/compile_native" "$REPO/src/compiler/tools/compile_native.iyi" > "$WORK/tool.build.log" 2>&1; then
  for name in $e2e; do
    fixture="$REPO/bench/fixtures/$name.iyi"
    if ! "$WORK/port" emit "$fixture" "$WORK/$name.oracle.ll" > "$WORK/$name.port.ir" 2> "$WORK/$name.emit.err"; then
      echo "  $name: the port writes no module: $(awk 'NR==1' "$WORK/$name.emit.err")"
      e2e_fail=$((e2e_fail + 1))
      continue
    fi
    if ! "$WORK/compile_native" "$WORK/$name.port.ir" -o "$WORK/$name.native" > "$WORK/$name.native.log" 2>&1; then
      if [ -n "$(e2e_waiting_on "$name")" ]; then
        echo "  $name: WAITING, $(e2e_waiting_on "$name"): $(awk 'NR==1' "$WORK/$name.native.log")"
        e2e_waiting=$((e2e_waiting + 1))
        continue
      fi
      echo "  $name: the native tool refuses the port's module: $(awk 'NR==1' "$WORK/$name.native.log")"
      e2e_fail=$((e2e_fail + 1))
      continue
    fi
    timeout 30 "$WORK/$name.native" > "$WORK/$name.native.out" 2>&1; ns=$?
    timeout 30 "$WORK/$name" > "$WORK/$name.hosted.out" 2>&1; hs=$?
    if [ "$ns" = "$hs" ] && cmp -s "$WORK/$name.native.out" "$WORK/$name.hosted.out"; then
      echo "  $name: native executable runs to the hosted result (status $hs, stdout identical)"
      e2e_pass=$((e2e_pass + 1))
      if [ -n "$(e2e_waiting_on "$name")" ]; then
        echo "    $name: runs now: take it off E2E_WAITING in this gate"
        e2e_fail=$((e2e_fail + 1))
      fi
    else
      echo "  $name: native status $ns, hosted $hs; stdout differs or status differs"
      e2e_fail=$((e2e_fail + 1))
    fi
  done
else
  echo "  the native tool does not build (see $WORK/tool.build.log)"
  e2e_fail=1
fi
  echo "  end to end: $e2e_pass fixture(s) run to the hosted result, $e2e_waiting waiting by name, $e2e_fail failed"
if [ "$e2e_fail" -gt 0 ] || [ "$e2e_pass" -eq 0 ]; then
  status=1
fi

echo
echo "== 4. Mutation proofs: the gate must catch each patch to the ported code"
# The check rebuilds the driver from the patched source and requires every primitive fixture
# to match the hosted module exactly. It returns 0 only on the unmutated behaviour.
lower_primitives_check() {
  "$IYI" build -o "$WORK/mut" "$REPO/bench/selfhost_lower_primitives_exercise.iyi" > "$WORK/mut.build.log" 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/lowprim_*.iyi; do
    name="$(basename "$fixture" .iyi)"
    # A fixture waiting by name cannot pass the check; the check covers the rest.
    [ -n "$(waiting_on "$name")" ] && continue
    [ -n "$(known_divergence "$name")" ] && continue
    "$WORK/mut" lower "$fixture" "$WORK/$name.oracle.ll" > "$WORK/mut.out" 2>/dev/null || return 1
    awk '/^SUMMARY identical=[0-9]+ total=[0-9]+ module=[01]$/ { split($2, a, "="); split($3, b, "="); if (a[2] != b[2] || b[2] == 0) bad = 1; n++ } END { exit (bad || n == 0) }' "$WORK/mut.out" || return 1
  done
  return 0
}
# The baseline: the unmutated port must pass the check, or every mutation below is caught for the wrong reason.
lower_primitives_check || { echo "  baseline: the unmutated primitives do not pass the check"; status=1; }
prove_mutation "the wrapping add is a subtraction" "$REPO/src/compiler/lower/primitives.iyi" \
  "    return low.builder.add(p1, p2)" "    return low.builder.sub(p1, p2)" -- lower_primitives_check || status=1
prove_mutation "the signed less-than is unsigned" "$REPO/src/compiler/lower/primitives.iyi" \
  "signed_pred(signed, IntPredicate::SLT, IntPredicate::ULT)" "signed_pred(signed, IntPredicate::ULT, IntPredicate::ULT)" -- lower_primitives_check || status=1
prove_mutation "the Char less-than is less-or-equal" "$REPO/src/compiler/lower/primitives.iyi" \
  "    if op == \"<\"" "    if op == \"<=\"" -- lower_primitives_check || status=1
prove_mutation "the Bool equality tests inequality" "$REPO/src/compiler/lower/primitives.iyi" \
  "    if op == \"==\"" "    if op == \"!=\"" -- lower_primitives_check || status=1
prove_mutation "the class type id is stored one struct over" "$REPO/src/compiler/lower/primitives.iyi" \
  "  zero = low.builder.const_int(low.module.types.int32, 0_i64)" "  zero = low.builder.const_int(low.module.types.int32, 1_i64)" -- lower_primitives_check || status=1

echo
if [ "$status" -eq 0 ]; then
  echo "PRIMITIVES LOWERING GATE PASSED"
else
  echo "PRIMITIVES LOWERING GATE FAILED"
fi
exit "$status"
