#!/usr/bin/env bash
# Fails when the typed lowering of constants and class variables (src/compiler/lower/{const,
# class_var,once}.iyi) stops agreeing with the hosted code generator's module for the same
# fixture. Written in the pattern of bench/selfhost_lower_core_exercise.sh and the calls gate;
# CI runs every bench/selfhost_*_exercise.sh, so this gate is one of them.
# every mutation is caught, and a fixture that refuses is named below.
#
# For each fixture (bench/fixtures/lowglob_*.iyi) the hosted compiler builds the program against
# --prelude empty, with --emit llvm-ir and --no-debug. Its module is read through the port's IR
# text parser; the port analyses the fixture, lowers it, and prints the module. The two normalised
# texts are compared function by function (bench/lib/lower_gate.iyi, shared with the other lowering
# gates). The oracle's direct calls get their function type from bench/lib/lower_oracle.sh.
#
# A fixture the port refuses by name is WAITING only when it is named in WAITING_FIXTURES below;
# an unnamed refusal fails the gate, and a named one that starts to match fails it too.
#
# Each fixture the port lowers identically is built to a native executable and run: the exit status
# and stdout must equal the hosted executable's. The fixtures return the constant through LibC.exit,
# so a wrong constant changes the status.
#
# Mutation proofs patch the ported code, rebuild the driver, and require the check to fail. A patch
# that changes nothing is refused by prove_mutation.
#
#   bash bench/selfhost_lower_globals_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
. "$REPO/bench/lib/mutation.sh"
. "$REPO/bench/lib/lower_oracle.sh"
WORK="$(mktemp -d)"

trap 'rm -rf "$WORK"' EXIT

# Fixtures the port refuses by name, for a reason in src/compiler/lower/NEEDS.md (none yet).
WAITING_FIXTURES=""

echo "== 1. Building the port driver"
if ! "$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_lower_globals_exercise.iyi" > "$WORK/port.build.log" 2>&1; then
  echo "  the driver does not build (see $WORK/port.build.log)"
  awk 'NR<=5' "$WORK/port.build.log"
  exit 1
fi
if "$WORK/port" > "$WORK/usage.out" 2>&1; then
  echo "  driver built, bare run exits 0"
else
  echo "  the driver's bare run fails (see $WORK/usage.out)"
  exit 1
fi

echo
echo "== 2. Each fixture: the hosted module against the port's lowering"
passed=0
waiting=0
diverged=0
e2e=""
for fixture in "$REPO"/bench/fixtures/lowglob_*.iyi; do
  name="$(basename "$fixture" .iyi)"
  if ! "$IYI" build --prelude empty --emit llvm-ir --no-debug -o "$WORK/$name" "$fixture" > "$WORK/$name.oracle.log" 2>&1 || [ ! -s "$WORK/$name.ll" ]; then
    echo "  $name: the hosted compiler did not emit its module (see $WORK/$name.oracle.log)"
    diverged=$((diverged + 1))
    continue
  fi
  awk "$CALL_TYPES" "$WORK/$name.ll" > "$WORK/$name.oracle.ll"
  if ! "$WORK/port" oracle "$WORK/$name.oracle.ll" > "$WORK/$name.oracle.txt" 2> "$WORK/$name.oracle.err"; then
    echo "  $name: the port's IR parser refuses the hosted module: $(awk 'NR==1' "$WORK/$name.oracle.err")"
    diverged=$((diverged + 1))
    continue
  fi
  named=0
  case " $WAITING_FIXTURES " in
    *" $name "*) named=1 ;;
  esac
  if ! "$WORK/port" lower "$fixture" "$WORK/$name.oracle.ll" > "$WORK/$name.port.out" 2> "$WORK/$name.port.err"; then
    reason="$(awk 'NR==1' "$WORK/$name.port.err")"
    if [ "$named" = 1 ]; then
      echo "  $name: WAITING, named: $reason"
      waiting=$((waiting + 1))
    else
      echo "  $name: REFUSED, not named as waiting: $reason"
      diverged=$((diverged + 1))
    fi
    continue
  fi
  echo "  $name:"
  awk '!/^SUMMARY/' "$WORK/$name.port.out" | awk '{ print "    " $0 }'
  summary="$(awk '/^SUMMARY/ { print }' "$WORK/$name.port.out")"
  identical="$(echo "$summary" | awk '{ split($2, a, "="); print a[2] }')"
  total="$(echo "$summary" | awk '{ split($3, a, "="); print a[2] }')"
  if [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$identical" = "$total" ]; then
    if [ "$named" = 1 ]; then
      echo "    $name: now identical to the hosted module: remove it from WAITING_FIXTURES"
      diverged=$((diverged + 1))
    fi
    echo "    $name: PASSED, $identical of $total identical (module-level and functions)"
    passed=$((passed + 1))
    e2e="$e2e $name"
  else
    echo "    $name: DIVERGED, $identical of $total identical"
    diverged=$((diverged + 1))
  fi
done
echo "  fixtures: $passed passed, $waiting waiting (named), $diverged failed"
if [ "$diverged" -gt 0 ] || [ "$passed" -eq 0 ]; then
  status=1
fi

echo
echo "== 3. End to end: each fixture the port lowers identically, built to a native executable and run"
e2e_pass=0
e2e_fail=0
if "$IYI" build -o "$WORK/compile_native" "$REPO/src/compiler/tools/compile_native.iyi" > "$WORK/tool.build.log" 2>&1; then
  for name in $e2e; do
    fixture="$REPO/bench/fixtures/$name.iyi"
    if ! "$WORK/port" emit "$fixture" "$WORK/$name.oracle.ll" > "$WORK/$name.port.ir" 2> "$WORK/$name.emit.err"; then
      echo "  $name: the port writes no module: $(awk 'NR==1' "$WORK/$name.emit.err")"
      e2e_fail=$((e2e_fail + 1))
      continue
    fi
    if ! "$WORK/compile_native" "$WORK/$name.port.ir" -o "$WORK/$name.native" > "$WORK/$name.native.log" 2>&1; then
      echo "  $name: the native tool refuses the port's module: $(awk 'NR==1' "$WORK/$name.native.log")"
      e2e_fail=$((e2e_fail + 1))
      continue
    fi
    timeout 30 "$WORK/$name.native" > "$WORK/$name.native.out" 2>&1; ns=$?
    timeout 30 "$WORK/$name" > "$WORK/$name.hosted.out" 2>&1; hs=$?
    if [ "$ns" = "$hs" ] && cmp -s "$WORK/$name.native.out" "$WORK/$name.hosted.out"; then
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
# The check rebuilds the driver from the patched source and requires every fixture to match the
# hosted module exactly. It returns 0 only on the unmutated behaviour.
lowglob_check() {
  "$IYI" build -o "$WORK/port_m" "$REPO/bench/selfhost_lower_globals_exercise.iyi" > "$WORK/port_m.build.log" 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/lowglob_*.iyi; do
    name="$(basename "$fixture" .iyi)"
    "$WORK/port_m" lower "$fixture" "$WORK/$name.oracle.ll" > "$WORK/m.out" 2>&1 || return 1
    summary="$(awk '/^SUMMARY/ { print }' "$WORK/m.out")"
    identical="$(echo "$summary" | awk '{ split($2, a, "="); print a[2] }')"
    total="$(echo "$summary" | awk '{ split($3, a, "="); print a[2] }')"
    [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$identical" = "$total" ] || return 1
  done
  return 0
}
echo "  the mutation check passes on the unmutated code:"
if lowglob_check; then
  echo "    unmutated: every fixture identical"
else
  echo "    FAIL: the unmutated code does not pass the check"
  status=1
fi
prove_mutation "a literal integer constant is one more than its value" "$REPO/src/compiler/lower/const.iyi" \
  "    return low.builder.const_int(low.typer.llvm_type(typ), text.to_i64)" \
  "    return low.builder.const_int(low.typer.llvm_type(typ), text.to_i64 + 1_i64)" -- lowglob_check || status=1
prove_mutation "a true Bool constant is false" "$REPO/src/compiler/lower/const.iyi" \
  "      return int1(low, 1_i64)" "      return int1(low, 0_i64)" -- lowglob_check || status=1
prove_mutation "a literal integer constant is refused rather than inlined" "$REPO/src/compiler/lower/const.iyi" \
  "    return low.builder.const_int(low.typer.llvm_type(typ), text.to_i64)" \
  "    return nil" -- lowglob_check || status=1
prove_mutation "the initialiser is not called at the assignment" "$REPO/src/compiler/lower/const.iyi" \
  '  low.builder.call(ft, fn.as(Function), [] of Value, "")' \
  '  low.builder.const_int(low.module.types.int(1), 0_i64)' -- lowglob_check || status=1
prove_mutation "a constant with a constant value is stored at run time, not folded" "$REPO/src/compiler/lower/const.iyi" \
  "  if val.is_a?(Inst) && (val.as(Inst).op == Op::ConstInt || val.as(Inst).op == Op::ConstFloat)" "  if false" -- lowglob_check || status=1
prove_mutation "a read of an initialised constant is not a load" "$REPO/src/compiler/lower/const.iyi" \
  "  low.last = load_aligned(low, ir, g.as(Global))" "  low.last = llvm_nil(low)" -- lowglob_check || status=1
prove_mutation "the constant initialiser has the iyi convention, not C" "$REPO/src/compiler/lower/const.iyi" \
  "  fn.call_convention = CallConv::C" "  fn.call_convention = CallConv::Iyi" -- lowglob_check || status=1

echo
if [ "$status" -eq 0 ]; then
  echo "lower globals gate: OK"
else
  echo "lower globals gate: FAILED"
fi
exit "$status"
