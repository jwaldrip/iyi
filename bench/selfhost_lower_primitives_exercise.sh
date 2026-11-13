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
    lowprim_enum) echo "enum members type as Int32 until the bodies lane's enum Path fix lands" ;;
  esac
}

# Fixtures that lower with a known divergence, named, not yet fixed. The gate fails if one starts to match,
# so the list stays honest.
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
  oracle_options=()
  if [ "$name" = "lowprim_atomic_rmw" ]; then
    # Otherwise the hosted module is printed after LLVM has expanded atomicrmw to a cmpxchg loop.
    oracle_options=(--mattr +lse)
    echo "  $name: oracle uses --mattr +lse to preserve atomicrmw in the emitted module"
  fi
  if ! "$IYI" build --prelude empty "${oracle_options[@]}" --emit llvm-ir --no-debug -o "$WORK/$name" "$fixture" > "$WORK/$name.oracle.log" 2>&1 || [ ! -s "$WORK/$name.ll" ]; then
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
binary_union_check() {
  for side in left right; do
    if "$1" binary_union "$REPO/bench/fixtures/prim_refuse_union.iyi" "$side" > "$WORK/union.out" 2> "$WORK/union.err"; then
      return 1
    fi
    awk '/lower: visit\(binary <= with operand IR types .* inconsistent with Int64 and Int64 \(hosted codegen_binary_op\)\)/ { found = 1 } END { exit !found }' "$WORK/union.err" || return 1
  done
}
if binary_union_check "$WORK/port"; then
  echo "  union comparison: both operand positions refused by name"
else
  echo "  union comparison: missing named refusal"
  status=1
fi

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
  "$WORK/mut" generic_pointerful > "$WORK/mut.pointerful" 2>"$WORK/mut.pointerful.err" || return 1
  awk '/^generic_pointerful=1$/ { found = 1 } END { exit !found }' "$WORK/mut.pointerful" || return 1
  binary_union_check "$WORK/mut" || return 1
  return 0
}
# The baseline: the unmutated port must pass the check, or every mutation below is caught for the wrong reason.
lower_primitives_check || { echo "  baseline: the unmutated primitives do not pass the check"; status=1; }
prove_mutation "binary union operand is not refused" "$REPO/src/compiler/lower/primitives.iyi" \
  '    if p1.type.key != low.typer.llvm_type(t1).key || p2.type.key != low.typer.llvm_type(t2).key' '    if false' -- lower_primitives_check || status=1
prove_mutation "the wrapping add is a subtraction" "$REPO/src/compiler/lower/primitives.iyi" \
  "    return low.builder.add(p1, p2)" "    return low.builder.sub(p1, p2)" -- lower_primitives_check || status=1
prove_mutation "the signed less-than is unsigned" "$REPO/src/compiler/lower/primitives.iyi" \
  "signed_pred(t1.signed, IntPredicate::SLT, IntPredicate::ULT)" "signed_pred(t1.signed, IntPredicate::ULT, IntPredicate::ULT)" -- lower_primitives_check || status=1
prove_mutation "the wrong side is extended" "$REPO/src/compiler/lower/primitives.iyi" \
  "    return ExtendedInts.new(t2, extend_int(low, t1, t2, p1), p2)" "    return ExtendedInts.new(t2, extend_int(low, t2, t1, p1), p2)" -- lower_primitives_check || status=1
prove_mutation "a sign extension is a zero extension" "$REPO/src/compiler/lower/primitives.iyi" \
  "    return low.builder.sext(value, to.ir)" "    return low.builder.zext(value, to.ir)" -- lower_primitives_check || status=1
prove_mutation "a mixed-sign less-than uses the unsigned predicate" "$REPO/src/compiler/lower/primitives.iyi" \
  "      widened = low.builder.icmp(IntPredicate::SLT, p1, extend_int(low, t2, t1, p2))" "      widened = low.builder.icmp(IntPredicate::ULT, p1, extend_int(low, t2, t1, p2))" -- lower_primitives_check || status=1
prove_mutation "a by-value pointer_get loads" "$REPO/src/compiler/lower/primitives.iyi" \
  "      low.last = values[0]" "      low.last = load_aligned(low, low.typer.llvm_embedded_type(elem), values[0])" -- lower_primitives_check || status=1
prove_mutation "a generic pointer metaclass receiver is not evaluated" "$REPO/src/compiler/lower/primitives.iyi" \
  '        type_id_value(low, receiver_type(low, receiver))' '        llvm_nil(low)' -- lower_primitives_check || status=1
prove_mutation "pointer addition loses inbounds" "$REPO/src/compiler/lower/primitives.iyi" \
  '    low.last = low.builder.inbounds_gep(low.typer.llvm_embedded_type(elem), values[0], [values[1]] of Value)' '    low.last = low.builder.gep(low.typer.llvm_embedded_type(elem), values[0], [values[1]] of Value)' -- lower_primitives_check || status=1
prove_mutation "a Bool pointer_set stores zero" "$REPO/src/compiler/lower/primitives.iyi" \
  "      bool_stored = values[1]" "      bool_stored = int1(low, 0_i64)" -- lower_primitives_check || status=1
prove_mutation "a generic instance ignores its class variables" "$REPO/src/compiler/lower/primitives.iyi" \
  "    return t.as(GenericClassInstanceType).all_instance_vars" "    return Hash(String, MetaTypeVar).new" -- lower_primitives_check || status=1
prove_mutation "a nilable reference union reads the nil id from the object" "$REPO/src/compiler/lower/cast.iyi" \
  "    phi.add(low, object_type_id(low, value), true)" "    phi.add(low, type_id_value(low, low.analysed.program.nil_type), true)" -- lower_primitives_check || status=1
prove_mutation "an implicit-self primitive uses a constant instead of self" "$REPO/src/compiler/lower/primitives.iyi" \
  "    recv = sv.as(LowerVar).pointer" "    recv = int1(low, 0_i64)" -- lower_primitives_check || status=1
prove_mutation "a reference pointer_set stores the pointer slot" "$REPO/src/compiler/lower/primitives.iyi" \
  "      ref_stored = values[1]" "      ref_stored = values[0]" -- lower_primitives_check || status=1
prove_mutation "a by-value pointer_set copies the destination" "$REPO/src/compiler/lower/primitives.iyi" \
  "    store_aligned(low, stored, dest)" "    store_aligned(low, load_aligned(low, ir, dest), dest)" -- lower_primitives_check || status=1
prove_mutation "checked addition returns its overflow bit" "$REPO/src/compiler/lower/primitives.iyi" \
  "  pair[0]" "  pair[1]" -- lower_primitives_check || status=1
prove_mutation "an acquire atomic load is sequentially consistent" "$REPO/src/compiler/lower/primitives.iyi" \
  '  when "acquire"                 then Ordering::Acquire' '  when "acquire"                 then Ordering::SeqCst' -- lower_primitives_check || status=1
prove_mutation "a release atomic store is sequentially consistent" "$REPO/src/compiler/lower/primitives.iyi" \
  '  when "release"                 then Ordering::Release' '  when "release"                 then Ordering::SeqCst' -- lower_primitives_check || status=1
prove_mutation "an atomic read-modify-write always exchanges" "$REPO/src/compiler/lower/primitives.iyi" \
  '  inst = low.builder.atomicrmw(op, ptr.as(Value), value, ordering, flag.as(BoolLiteral).value)' '  inst = low.builder.atomicrmw("xchg", ptr.as(Value), value, ordering, flag.as(BoolLiteral).value)' -- lower_primitives_check || status=1
prove_mutation "an atomic read-modify-write ignores its ordering" "$REPO/src/compiler/lower/primitives.iyi" \
  '  ordering = atomic_ordering(node.args[3])' '  ordering = Ordering::Monotonic' -- lower_primitives_check || status=1
prove_mutation "compare-exchange ignores its failure ordering" "$REPO/src/compiler/lower/primitives.iyi" \
  '  result = low.builder.cmpxchg(ptr.as(Value), compare, replacement, success, failure)' '  result = low.builder.cmpxchg(ptr.as(Value), compare, replacement, success, success)' -- lower_primitives_check || status=1
if [ -n "$(waiting_on lowprim_enum)" ]; then
  echo "  NOT RUN: enum mutation waits for enum member typing"
else
  prove_mutation "an enum value is not lowered" "$REPO/src/compiler/lower/primitives.iyi" \
    '  if name == "enum_value"' '  if name == "wrong_enum_value"' -- lower_primitives_check || status=1
fi
prove_mutation "checked conversion omits its lower bound" "$REPO/src/compiler/lower/primitives.iyi" \
  '  low.builder.build_or(below, above)' '  above' -- lower_primitives_check || status=1
prove_mutation "checked conversion omits its upper bound" "$REPO/src/compiler/lower/primitives.iyi" \
  '  low.builder.build_or(below, above)' '  below' -- lower_primitives_check || status=1
prove_mutation "a tuple index selects the first member" "$REPO/src/compiler/lower/primitives.iyi" \
  '  first = primitive.tuple_index' '  first = 0' -- lower_primitives_check || status=1
prove_mutation "object_id returns zero instead of the receiver address" "$REPO/src/compiler/lower/primitives.iyi" \
  '    low.last = low.builder.ptr_to_int(values[0], low.module.types.int64)' '    low.last = low.builder.const_int(low.module.types.int64, 0_i64)' -- lower_primitives_check || status=1
prove_mutation "runtime type id returns Nil's id" "$REPO/src/compiler/lower/primitives.iyi" \
  '      low.last = type_id_of_value(low, obj || node, values[0], t1)' '      low.last = type_id_value(low, low.analysed.program.nil_type)' -- lower_primitives_check || status=1
prove_mutation "proc call omits the closure context" "$REPO/src/compiler/lower/primitives.iyi" \
  '  closure_args = [ctx.as(Value)] of Value' '  closure_args = [] of Value' -- lower_primitives_check || status=1
prove_mutation "a nil proc call merges Nil values" "$REPO/src/compiler/lower/primitives.iyi" \
  '  phi = LowerPhi.new(wants && !proc_type.return_type.nil_type? && !ret_type.void?, ret_type)' '  phi = LowerPhi.new(wants && !ret_type.void?, ret_type)' -- lower_primitives_check || status=1
prove_mutation "tuple metaclass indexing returns Nil's type id" "$REPO/src/compiler/lower/primitives.iyi" \
  '    low.last = type_id_value(low, result.as(Type))' '    low.last = type_id_value(low, low.analysed.program.nil_type)' -- lower_primitives_check || status=1
prove_mutation "the Char less-than is less-or-equal" "$REPO/src/compiler/lower/primitives.iyi" \
  "    if op == \"<\"" "    if op == \"<=\"" -- lower_primitives_check || status=1
prove_mutation "the Bool equality tests inequality" "$REPO/src/compiler/lower/primitives.iyi" \
  "    if op == \"==\"" "    if op == \"!=\"" -- lower_primitives_check || status=1
prove_mutation "the class type id is stored one struct over" "$REPO/src/compiler/lower/primitives.iyi" \
  "  zero = low.builder.const_int(low.module.types.int32, 0_i64)" "  zero = low.builder.const_int(low.module.types.int32, 1_i64)" -- lower_primitives_check || status=1

echo
echo "== 5. Checked arithmetic in an isolated def from a required runtime"
required="$REPO/bench/fixtures/lower_overflow_required"
if IYI_PATH="$required/prelude" "$IYI" build --emit llvm-ir --no-debug -o "$WORK/required-oracle" "$required/main.iyi" > "$WORK/required-oracle.log" 2>&1; then
  awk "$CALL_TYPES" "$WORK/required-oracle.ll" > "$WORK/required-oracle.normal.ll"
  "$WORK/port" oracle "$WORK/required-oracle.normal.ll" > "$WORK/required-host.txt" 2> "$WORK/required-host.err" || status=1
  awk '/^define .*checked_sum/{p=1; n++} p{print} p && /^}/{p=0} END {if (n != 1) exit 1}' "$WORK/required-host.txt" > "$WORK/required-host.fn" || status=1
else
  echo "  required-unit oracle failed:"
  awk 'NR<=15' "$WORK/required-oracle.log"
  status=1
fi
required_overflow_check() {
  "$IYI" build -o "$WORK/required-port" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/required-build.log" 2>&1 || return 1
  (cd "$required" && "$WORK/required-port" probe-required runtime.iyi main.iyi "$WORK/required-oracle.normal.ll") > "$WORK/required.ir" 2> "$WORK/required.err" || return 1
  awk '/^declare external void @__iyi_raise_overflow/ {found=1} END {exit !found}' "$WORK/required.ir" || return 1
  "$WORK/port" oracle "$WORK/required.ir" > "$WORK/required-port.txt" 2> "$WORK/required-port.err" || return 1
  awk '/^define .*checked_sum/{p=1; n++} p{print} p && /^}/{p=0} END {if (n != 1) exit 1}' "$WORK/required-port.txt" > "$WORK/required-port.fn" || return 1
  cmp -s "$WORK/required-host.fn" "$WORK/required-port.fn"
}
if required_overflow_check; then
  echo "  required-unit overflow: function identical to the hosted module"
else
  echo "  required-unit overflow: refused or differs from the hosted module"
  awk 'NR<=12' "$WORK/required.err" "$WORK/required-build.log"
  status=1
fi
prove_mutation "the required overflow function has the wrong name" "$REPO/src/compiler/lower/primitives.iyi" \
  '    fn = low.module.add_function(name, fn_type, CallConv::C)' '    fn = low.module.add_function(name + "_wrong", fn_type, CallConv::C)' -- required_overflow_check || status=1

echo
if [ "$status" -eq 0 ]; then
  echo "PRIMITIVES LOWERING GATE PASSED"
else
  echo "PRIMITIVES LOWERING GATE FAILED"
fi
exit "$status"
