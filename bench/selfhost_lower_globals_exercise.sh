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

# The shared comparator (bench/lib/lower_gate.iyi) counts only the functions it reproduces: a module-level item (a global,
# a declaration) that differs is reported but not counted. This gate also requires the module-level items to match.
module_same() { awk '/module-level: identical/ { found = 1 } END { exit !found }' "$1"; }

trap 'rm -rf "$WORK"' EXIT

# The class-variable reads on a class receiver (K.v) pass now that the calls lane lowers class-receiver calls (S2c8Calls).
WAITING_FIXTURES="lowglob_cvar_tls lowglob_cvar_lazy"
# The body pass does not flag an untyped @[ThreadLocal] declaration.
# The lazy fixture's indirect Proc call waits on body typing's splat binding.
#
# The hosted lazy fixture is nevertheless run and its flag-check mutation tested below.

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

# The shared oracle normalizer must add the function type for an indirect call,
# but must not guess the type of an aggregate argument.
oracle_call_checks() {
  awk "$CALL_TYPES" "$REPO/bench/fixtures/lowglob_indirect.ll" > "$WORK/indirect.ir"
  "$1" oracle "$WORK/indirect.ir" > "$WORK/indirect.out" 2>&1 || return 1
  awk "$CALL_TYPES" "$REPO/bench/fixtures/lowglob_indirect_aggregate.ll" > "$WORK/aggregate.ir"
  cmp -s "$REPO/bench/fixtures/lowglob_indirect_aggregate.ll" "$WORK/aggregate.ir" || return 1
  "$1" oracle "$WORK/aggregate.ir" > "$WORK/aggregate.out" 2>&1 && return 1
  awk '/expected `\(` but found/ { found = 1 } END { exit !found }' "$WORK/aggregate.out"
}
if oracle_call_checks "$WORK/port"; then
  echo "  indirect oracle call parses; multiword argument is unchanged and refused"
else
  echo "  FAIL: indirect oracle normalization"
  status=1
fi


# A lazily initialised class variable needs the hosted compiler to look up __iyi_once. A prelude
# named empty leaves iyi_prelude? false, so that fixture is built against a prelude whose require
# name ends in iyi/prelude (bench/fixtures/lowglob_abi). The fixture declares IyiRuntimeLock.
hosted_module() {
  name="$1"
  fixture="$2"
  out="$3"
  log="$4"
  case "$name" in
    lowglob_cvar_lazy*)
      built_in=$("$IYI" env | awk -F= '/^IYI_PATH=/ { print substr($0, index($0, "=") + 1); exit }')
      IYI_PATH="$REPO/bench/fixtures/lowglob_abi:${built_in}" "$IYI" build --prelude iyi/prelude --emit llvm-ir --no-debug -o "$out" "$fixture" > "$log" 2>&1
      ;;
    *) "$IYI" build --prelude empty --emit llvm-ir --no-debug -o "$out" "$fixture" > "$log" 2>&1 ;;
  esac
}

# Exit 1 means the initializer's side effect happened exactly once. A dropped flag
# check makes the counter 2, even if the value global itself happens to look right.
hosted_once_check() {
  hosted_module lowglob_cvar_lazy "$REPO/bench/fixtures/lowglob_cvar_lazy.iyi" "$WORK/once_check" "$WORK/once_check.log" || return 1
  timeout 30 "$WORK/once_check" > "$WORK/once_check.out" 2>&1
  [ "$?" -eq 1 ]
}

echo
echo "== 2. Each fixture: the hosted module against the port's lowering"
passed=0
waiting=0
diverged=0
e2e=""
for fixture in "$REPO"/bench/fixtures/lowglob_*.iyi; do
  name="$(basename "$fixture" .iyi)"
  if ! hosted_module "$name" "$fixture" "$WORK/$name" "$WORK/$name.oracle.log" || [ ! -s "$WORK/$name.ll" ]; then
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
    if [ "$name" = lowglob_cvar_lazy ]; then
      case "$reason" in
        *"expected type, got *T"*) ;;
        *) echo "  $name: unexpected refusal: $reason"; diverged=$((diverged + 1)); continue ;;
      esac
    fi
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
  if [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$identical" = "$total" ] && module_same "$WORK/$name.port.out"; then
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
timeout 30 "$WORK/lowglob_cvar_lazy" > "$WORK/lazy-hosted.out" 2>&1
lazy_status=$?
if [ "$lazy_status" -eq 1 ]; then
  echo "  hosted lazy initialization: side effect occurred exactly once (status 1)"
else
  echo "  hosted lazy initialization: expected status 1, got $lazy_status"
  diverged=$((diverged + 1))
fi
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
  "$WORK/port_m" normalizer-check > /dev/null 2>&1 || return 1
  ( . "$REPO/bench/lib/lower_oracle.sh"; oracle_call_checks "$WORK/port_m" ) || return 1
  for fixture in "$REPO"/bench/fixtures/lowglob_*.iyi; do
    name="$(basename "$fixture" .iyi)"
    case " $WAITING_FIXTURES " in *" $name "*) "$WORK/port_m" lower "$fixture" "$WORK/$name.oracle.ll" > /dev/null 2>&1 && return 1; continue ;; esac
    "$WORK/port_m" lower "$fixture" "$WORK/$name.oracle.ll" > "$WORK/m.out" 2>&1 || return 1
    summary="$(awk '/^SUMMARY/ { print }' "$WORK/m.out")"
    identical="$(echo "$summary" | awk '{ split($2, a, "="); print a[2] }')"
    total="$(echo "$summary" | awk '{ split($3, a, "="); print a[2] }')"
    [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$identical" = "$total" ] && module_same "$WORK/m.out" || return 1
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
prove_mutation "a program global is incorrectly stripped as a build constant" "$REPO/bench/lib/lower_gate.iyi" \
  "        if destination.starts_with?(prefix) && identity_names.includes?(destination[prefix.size..-1])" "        if destination.includes?(marker)" -- lowglob_check || status=1
prove_mutation "indirect calls are left without a function type" "$REPO/bench/lib/lower_oracle.sh" \
  "  if (at == 0) return line" "  if (indirect || at == 0) return line" -- lowglob_check || status=1
prove_mutation "lazy initializer ignores the once flag" "$REPO/bench/fixtures/lowglob_cvar_lazy.iyi" \
  "  if !flag.value" "  if true" -- hosted_once_check || status=1
prove_mutation "a nilable Proc initializer is not discarded" "$REPO/src/compiler/lower/class_var.iyi" \
  "  node.is_a?(NilLiteral) && cvar.type.is_a?(NilableProcType)" "  false" -- lowglob_check || status=1
prove_mutation "a pointer class variable is refused" "$REPO/src/compiler/lower/class_var.iyi" \
  "  if !(ir.int? || ir.float? || ir.pointer?)" "  if !(ir.int? || ir.float?)" -- lowglob_check || status=1
prove_mutation "a nil aggregate initializer is refused" "$REPO/src/compiler/lower/class_var.iyi" \
  "  if nilable_aggregate_initializer?(cvar)" "  if false" -- lowglob_check || status=1
prove_mutation "an aggregate class variable is loaded instead of read by address" "$REPO/src/compiler/lower/class_var.iyi" \
  "  low.last = to_lhs(low, class_var_pointer(low, cvar), cvar.type)" \
  "  low.last = load_aligned(low, cvar_ir_type(low, cvar), class_var_pointer(low, cvar))" -- lowglob_check || status=1
prove_mutation "a by-value constant is loaded instead of read by address" "$REPO/src/compiler/lower/const.iyi" \
  "      low.last = to_lhs(low, g.as(Global), low.analysed.type_of?(c.value).as(Type))" \
  "      low.last = load_aligned(low, ir, g.as(Global))" -- lowglob_check || status=1
prove_mutation "an indirectly passed constant is copied as a fresh slot" "$REPO/src/compiler/lower/const.iyi" \
  "        copy_pointer_value(low, global, val, ir, false)" \
  "        copy_pointer_value(low, global, val, ir, true)" -- lowglob_check || status=1
prove_mutation "a type path returns zero instead of its type id" "$REPO/src/compiler/lower/const.iyi" \
  "    low.last = type_id_value(low, typ.as(Type))" \
  "    low.last = low.builder.const_int(low.module.types.int32, 0_i64)" -- lowglob_check || status=1
prove_mutation "a floating constant global is initialized to zero" "$REPO/src/compiler/lower/const.iyi" \
  "    global.initializer = low.builder.const_float(ir, const.value.as(NumberLiteral).value.to_f)" \
  "    global.initializer = low.builder.const_float(ir, 0.0)" -- lowglob_check || status=1
prove_mutation "a symbol constant global has the wrong index" "$REPO/src/compiler/lower/const.iyi" \
  "    global.initializer = low.builder.const_int(ir, symbol_index(low, const.value.as(SymbolLiteral).value).to_i64)" \
  "    global.initializer = low.builder.const_int(ir, 1_i64)" -- lowglob_check || status=1
prove_mutation "a symbol class variable does not retain its literal index" "$REPO/src/compiler/lower/class_var.iyi" \
  "    value = low.builder.const_int(ir, symbol_index(low, node.as(SymbolLiteral).value).to_i64)" \
  "    value = low.builder.const_int(ir, symbol_index(low, node.as(SymbolLiteral).value).to_i64 + 1_i64)" -- lowglob_check || status=1
prove_mutation "a nil reference initializer is not discarded" "$REPO/src/compiler/lower/class_var.iyi" \
  "  node.is_a?(NilLiteral) && nilable_reference_type?(cvar.type)" \
  "  false" -- lowglob_check || status=1
prove_mutation "a namespaced class variable loses its qualified owner" "$REPO/src/compiler/lower/class_var.iyi" \
  "  owner.full_name + cvar_suffix(name)" \
  "  owner.name + cvar_suffix(name)" -- lowglob_check || status=1
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
prove_mutation "the constant initialiser has the C convention, not iyi" "$REPO/src/compiler/lower/const.iyi" \
  "  fn.call_convention = CallConv::Iyi" "  fn.call_convention = CallConv::C" -- lowglob_check || status=1
prove_mutation "a class variable read is not a load of its global" "$REPO/src/compiler/lower/class_var.iyi" \
  "  low.last = to_lhs(low, class_var_pointer(low, cvar), cvar.type)" "  low.last = llvm_nil(low)" -- lowglob_check || status=1
prove_mutation "a literal class variable is initialised by a function, not stored at its declaration" "$REPO/src/compiler/lower/class_var.iyi" \
  "  if simple_literal?(node)" "  if false" -- lowglob_check || status=1
prove_mutation "a string constant's global is not emitted at the program's start" "$REPO/src/compiler/lower/const.iyi" \
  "initialize_simple_const(low, const)" \
  "low.last = llvm_nil(low)" -- lowglob_check || status=1
prove_mutation "a string constant's global is initialised with null, not its address" "$REPO/src/compiler/lower/const.iyi" \
  "global.initializer = str.as(Value)" \
  "global.initializer = low.builder.const_null(ir)" -- lowglob_check || status=1
prove_mutation "a string constant's assignment initialises it a second time" "$REPO/src/compiler/lower/const.iyi" \
  "if string_const?(c)" \
  "if false" -- lowglob_check || status=1
prove_mutation "a class variable assignment in a method stores the global's address, not the value" "$REPO/src/compiler/lower/class_var.iyi" \
  "  store_aligned(low, value, ptr)" \
  "  store_aligned(low, ptr, ptr)" -- lowglob_check || status=1
prove_mutation "a nilable reference class variable's global has no null initialiser" "$REPO/src/compiler/lower/class_var.iyi" \
  "    g.initializer = low.builder.const_null(ir)" "    g.initializer = nil" -- lowglob_check || status=1
prove_mutation "a @[ThreadLocal] class variable is lowered as a plain global (its refusal is lifted)" "$REPO/src/compiler/lower/lower.iyi" \
  '  if node.is_a?(Annotation) && node.as(Annotation).path.names.last == "ThreadLocal"' "  if false" -- lowglob_check || status=1
prove_mutation "a typed @[ThreadLocal] class variable is lowered as a plain global (its flag is ignored)" "$REPO/src/compiler/lower/class_var.iyi" \
  "  if cvar.thread_local" "  if false" -- lowglob_check || status=1
prove_mutation "a thread-local class variable is read through its global, not its accessor" "$REPO/src/compiler/lower/class_var.iyi" \
  "  thread_local_address(low, cvar, name, g)" "  g" -- lowglob_check || status=1
prove_mutation "a UInt64 literal above Int64 max loses its sign bit" "$REPO/src/compiler/lower/const.iyi" \
  ".to_i64 &- 9223372036854775807_i64 &- 1_i64" ".to_i64" -- lowglob_check || status=1
prove_mutation "a namespaced constant is named by its bare name, not its full name" "$REPO/src/compiler/lower/const.iyi" \
  "  return const.full_name" "  return const.name" -- lowglob_check || status=1
prove_mutation "a required file's class variable literal ignores its declared type" "$REPO/src/compiler/lower/class_var.iyi" \
  "    value = literal_of_type(low, node, declared)" \
  "    value = nil" -- lowglob_check || status=1
prove_mutation "pointerof of a class variable is refused" "$REPO/src/compiler/lower/lower.iyi" \
  "    if exp.is_a?(ClassVar)" \
  "    if false" -- lowglob_check || status=1
prove_mutation "a float class-variable literal is not stored" "$REPO/src/compiler/lower/const.iyi" \
  "    return low.builder.const_float(low.typer.llvm_type(typ), text.to_f)" \
  "    return nil" -- lowglob_check || status=1
prove_mutation "a class variable initializer stores null instead of its value" "$REPO/src/compiler/lower/class_var.iyi" \
  "    store_aligned(low, val, global)" \
  "    store_aligned(low, low.builder.const_null(ir), global)" -- lowglob_check || status=1
prove_mutation "the initialiser function is not passed to once" "$REPO/src/compiler/lower/const.iyi" \
  '  low.builder.call_aux(CallAux.new(ft, CallConv::C), once_fn, [flag.as(Value), fn.as(Value)] of Value, "")' \
  '  low.builder.call_aux(CallAux.new(ft, CallConv::C), once_fn, [flag.as(Value), flag.as(Value)] of Value, "")' -- lowglob_check || status=1


echo
if [ "$status" -eq 0 ]; then
  echo "lower globals gate: OK"
else
  echo "lower globals gate: FAILED"
fi
exit "$status"
