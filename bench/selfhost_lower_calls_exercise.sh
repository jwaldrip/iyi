#!/usr/bin/env bash
# Fails when the typed lowering of calls and functions (src/compiler/lower/{fun,call}.iyi)
# stops agreeing with the hosted code generator's module for the same fixture.
#
# For each fixture (bench/fixtures/lowcall_*.iyi) the hosted compiler builds the program
# against --prelude empty, with --emit llvm-ir and --no-debug. Its module is read through
# the port's IR text parser and printed by the port's printer. The port analyses the
# fixture, lowers it, and prints the module. The two normalised texts are compared
# function by function (bench/lib/lower_gate.iyi, shared with the lowering-core gate).
#
# The oracle's direct calls get their function type and lose their call-site attribute
# group from bench/lib/lower_oracle.sh (CALL_TYPES), the same as the core gate.
#
# Each fixture the port lowers identically is then built to a native executable by the
# native tool and run: its exit status and stdout must equal the hosted executable's. The
# fixtures return computed values through `LibC.exit`, so the status is observable.
#
# The analysis types each lib and the calls on it (the semantic pass, semantic/lib_call.iyi).
#
# Mutation proofs patch the ported code, rebuild the driver, and require the check to
# fail. A patch that changes nothing is refused by prove_mutation.
#
#   bash bench/selfhost_lower_calls_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
. "$REPO/bench/lib/mutation.sh"
. "$REPO/bench/lib/lower_oracle.sh"
WORK="$(mktemp -d)"

# lowcall_capture_none waits on a real Proc#call: S1wDefaults3 expands the call to an
# arity-specific target, and S2d13Primitives supplies the Primitive body. The gate fails if
# that fixture stops refusing by this name, and it returns to the passing list when Proc lands.
WAITING_FIXTURES="lowcall_capture_none"
waiting_reason() {
  case "$1" in
    lowcall_capture_none) printf "%s" "undefined method 'call' for Proc(Int32)" ;;
    *) printf "%s" "" ;;
  esac
}

trap 'rm -rf "$WORK"' EXIT

echo "== 1. Building the port driver"
if ! "$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_lower_calls_exercise.iyi" > "$WORK/port.build.log" 2>&1; then
  echo "the port driver failed to build:"
  awk '!/^ld: warning/ && NR<=20' "$WORK/port.build.log"
  exit 1
fi
echo "  driver built"

echo
echo "== 2. Each fixture: the hosted module against the port's lowering"
passed=0
waiting=0
e2e=""
diverged=0
for fixture in "$REPO"/bench/fixtures/lowcall_*.iyi; do
  name="$(basename "$fixture" .iyi)"
  if ! "$IYI" build --prelude empty --emit llvm-ir --no-debug -o "$WORK/$name" "$fixture" > "$WORK/$name.oracle.log" 2>&1 || [ ! -s "$WORK/$name.ll" ]; then
    echo "  $name: the hosted compiler did not emit its module (see $WORK/$name.oracle.log)"
    diverged=$((diverged + 1))
    continue
  fi
  awk "$CALL_TYPES" "$WORK/$name.ll" > "$WORK/$name.oracle.ll"

  if ! "$WORK/port" lower "$fixture" "$WORK/$name.oracle.ll" > "$WORK/$name.port.out" 2> "$WORK/$name.port.err"; then
    reason="$(awk 'NR==1' "$WORK/$name.port.err")"
    expected="$(waiting_reason "$name")"
    if [ -n "$expected" ]; then
      case "$reason" in
        *"$expected"*)
          echo "  $name: WAITING, $expected (S1wDefaults3 expansion, S2d13Primitives Proc primitive): $reason"
          waiting=$((waiting + 1))
          ;;
        *)
          echo "  $name: unexpected refusal: $reason"
          diverged=$((diverged + 1))
          ;;
      esac
    else
      echo "  $name: REFUSED: $reason"
      diverged=$((diverged + 1))
    fi
    continue
  fi
  echo "  $name:"
  awk '!/^SUMMARY/ { print "    " $0 }' "$WORK/$name.port.out"
  summary="$(awk '/^SUMMARY/ { print }' "$WORK/$name.port.out")"
  identical="$(echo "$summary" | awk '{ split($2, a, "="); print a[2] }')"
  total="$(echo "$summary" | awk '{ split($3, a, "="); print a[2] }')"
  module="$(echo "$summary" | awk '{ split($4, a, "="); print a[2] }')"
  if [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$identical" = "$total" ] && [ "$module" = 1 ]; then
    if [ -n "$(waiting_reason "$name")" ]; then
      echo "    $name: now identical to the hosted module: remove it from WAITING_FIXTURES"
      diverged=$((diverged + 1))
    fi
    echo "    $name: PASSED, $identical of $total functions identical"
    passed=$((passed + 1))
    e2e="$e2e $name"
  else
    echo "    $name: DIVERGED, $identical of $total functions identical"
    diverged=$((diverged + 1))
  fi
done
echo "  fixtures: $passed passed, $waiting waiting (named), $diverged diverged or refused"
if [ "$diverged" -gt 0 ] || [ "$passed" -eq 0 ]; then
  status=1
fi

# An uninstantiated generic receiver is a typing gap, not an owner that lowering
# may guess. The hosted compiler still accepts the source and emits its module.
generic_fixture="$REPO/bench/fixtures/lowcallwait_uninstantiated_generic.iyi"
if "$IYI" build --prelude empty --emit llvm-ir --no-debug -o "$WORK/uninstantiated" "$generic_fixture" > "$WORK/uninstantiated.oracle.log" 2>&1; then
  awk "$CALL_TYPES" "$WORK/uninstantiated.ll" > "$WORK/uninstantiated.oracle.ll"
  if "$WORK/port" lower "$generic_fixture" "$WORK/uninstantiated.oracle.ll" > "$WORK/uninstantiated.out" 2> "$WORK/uninstantiated.err"; then
    echo "  uninstantiated generic: unexpectedly lowered"
    status=1
  elif awk 'index($0, "the receiver of probe is the uninstantiated generic Range(B, E).class: typing has not instantiated the owner") { found = 1 } END { exit !found }' "$WORK/uninstantiated.err"; then
    echo "  uninstantiated generic: typing gap identified"
  else
    echo "  uninstantiated generic: unexpected refusal: $(awk 'NR==1' "$WORK/uninstantiated.err")"
    status=1
  fi
else
  echo "  uninstantiated generic: hosted compiler refused the fixture"
  status=1
fi

echo
echo "== 3. End to end: each fixture the port lowers identically, built natively and run"
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
# The check rebuilds the driver from the patched source and requires every call fixture
# to match the hosted module exactly. It returns 0 only on the unmutated behaviour.
lower_calls_check() {
  "$IYI" build -o "$WORK/mut" "$REPO/bench/selfhost_lower_calls_exercise.iyi" > "$WORK/mut.build.log" 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/lowcall_*.iyi; do
    name="$(basename "$fixture" .iyi)"
    if [ -n "$(waiting_reason "$name")" ]; then
      "$WORK/mut" lower "$fixture" "$WORK/$name.oracle.ll" > "$WORK/mut.out" 2> "$WORK/mut.err" && return 1
      expected="$(waiting_reason "$name")"
      awk -v expected="$expected" 'index($0, expected) { found = 1 } END { exit !found }' "$WORK/mut.err" || return 1
      continue
    fi
    "$WORK/mut" lower "$fixture" "$WORK/$name.oracle.ll" > "$WORK/mut.out" 2>/dev/null || return 1
    awk '/^SUMMARY identical=[0-9]+ total=[0-9]+ module=[01]$/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); if (a[2] != b[2] || b[2] == 0 || c[2] != 1) bad = 1; n++ } END { exit (bad || n == 0) }' "$WORK/mut.out" || return 1
  done
  return 0
}
# A mutation is caught only when the unmutated port matches the hosted module: a check that fails on the
# unmutated tree would "catch" every patch, so the baseline must pass first.
if ! lower_calls_check; then
  echo "  baseline: the unmutated port does not match the hosted module, so no mutation below is counted"
  exit 1
fi
generic_gap_check() {
  "$IYI" build -o "$WORK/mut" "$REPO/bench/selfhost_lower_calls_exercise.iyi" > "$WORK/mut.build.log" 2>&1 || return 1
  if "$WORK/mut" lower "$generic_fixture" "$WORK/uninstantiated.oracle.ll" > "$WORK/generic.mut.out" 2> "$WORK/generic.mut.err"; then
    return 1
  fi
  awk 'index($0, "the receiver of probe is the uninstantiated generic Range(B, E).class: typing has not instantiated the owner") { found = 1 } END { exit !found }' "$WORK/generic.mut.err"
}
if ! generic_gap_check; then
  echo "  baseline: uninstantiated generic diagnostic did not match"
  exit 1
fi
prove_mutation "an uninstantiated generic loses its typing-gap diagnostic" "$REPO/src/compiler/lower/call.iyi" \
  '    if inst.is_a?(GenericClassType)' '    if false' -- generic_gap_check || status=1
# The import of a lib fun (contract 6b): the port's own text declares SecRandomCopyBytes with its framework. The
# comparison above drops the `import` text on both sides (lower_gate.iyi strip_import), so this check is the one
# that proves it. It rebuilds the driver from the current source, so a mutation of the import is what it tests.
link_import_check() {
  "$IYI" build -o "$WORK/mut" "$REPO/bench/selfhost_lower_calls_exercise.iyi" > "$WORK/mut.build.log" 2>&1 || return 1
  "$WORK/mut" emit "$REPO/bench/fixtures/lowcall_link_framework.iyi" "$WORK/lowcall_link_framework.oracle.ll" > "$WORK/mut.import.ir" 2>/dev/null || return 1
  awk '/^declare / && /@SecRandomCopyBytes\(/ && / import "Security"/ { ok = 1 } END { exit !ok }' "$WORK/mut.import.ir"
}
echo "  the lib fun is imported from its framework (contract 6b):"
if link_import_check; then
  echo "    yes: SecRandomCopyBytes is declared import \"Security\""
else
  echo "    no: the port's module does not declare SecRandomCopyBytes import \"Security\""
  status=1
fi
prove_mutation "a lib fun is imported from no library" "$REPO/src/compiler/lower/call.iyi" \
  "    made.import_library = import_from" "    made.import_library = nil" -- link_import_check || status=1
prove_mutation "a function's linkage is external" "$REPO/src/compiler/lower/fun.iyi" \
  "fn.linkage = Linkage::Internal" "fn.linkage = Linkage::External" -- lower_calls_check || status=1
prove_mutation "a mangled argument list has no separator" "$REPO/src/compiler/lower/fun.iyi" \
  'text = text + "<" + names.join(", ") + ">"' 'text = text + "<" + names.join(",") + ">"' -- lower_calls_check || status=1
prove_mutation "a call's result is discarded for nil" "$REPO/src/compiler/lower/call.iyi" \
  "    low.last = inst" "    low.last = llvm_nil(low)" -- lower_calls_check || status=1
prove_mutation "a lib call omits the unreachable after NoReturn" "$REPO/src/compiler/lower/call.iyi" \
  "    low.builder.unreachable" "    low.last = llvm_nil(low)" -- lower_calls_check || status=1
prove_mutation "the return after a terminated block is not skipped" "$REPO/src/compiler/lower/fun.iyi" \
  "  return if block_ended?(low)" "  low.last = low.last" -- lower_calls_check || status=1
prove_mutation "a def's unwind table is async on aarch64" "$REPO/src/compiler/lower/fun.iyi" \
  'return "sync"' 'return "async"' -- lower_calls_check || status=1
prove_mutation "a def loses its darwin frame pointers" "$REPO/src/compiler/lower/fun.iyi" \
  "  if darwin_triple?(triple)" "  if false" -- lower_calls_check || status=1
prove_mutation "the printer writes uwtable as an attribute, not uwtable(sync)" "$REPO/src/compiler/ir/printer.iyi" \
  'return "uwtable(" + s + ")" if a.name == "uwtable"' 'return "uwtable=" + ir_quote(s) if a.name == "uwtable"' -- lower_calls_check || status=1
prove_mutation "a NoReturn def carries no noreturn attribute" "$REPO/src/compiler/lower/fun.iyi" \
  'Attribute.new("noreturn", 0_u64, nil, nil)' 'Attribute.new("nounwind", 0_u64, nil, nil)' -- lower_calls_check || status=1
prove_mutation "a call to a def passes no arguments" "$REPO/src/compiler/lower/call.iyi" \
  'inst = low.builder.call(func.fn_type, func, call_arguments(self_value, values), "")' 'inst = low.builder.call(func.fn_type, func, [] of Value, "")' -- lower_calls_check || status=1
prove_mutation "a NoReturn def call is not followed by unreachable" "$REPO/src/compiler/lower/call.iyi" \
  "  if ret.is_a?(NoReturnType)
    low.builder.unreachable" "  if ret.is_a?(NilType)
    low.builder.unreachable" -- lower_calls_check || status=1
prove_mutation "a block argument is never stored at a yield" "$REPO/src/compiler/lower/block.iyi" \
  "        store_local(low, var.as(LowerVar), exp_types[i], exp_values[i])" "        low.last = low.last" -- lower_calls_check || status=1
prove_mutation "a block call's value is merged as a non-final branch" "$REPO/src/compiler/lower/call.iyi" \
  "  phi.add(low, low.last, true)" "  phi.add(low, low.last, false)" -- lower_calls_check || status=1
prove_mutation "a block call allocates none of the block's variables" "$REPO/src/compiler/lower/call.iyi" \
  "  allocate_block_vars(low, block, block_ctx.vars)" "  block_ctx.vars.size" -- lower_calls_check || status=1
prove_mutation "an inlined def's argument is allocated with the nil type" "$REPO/src/compiler/lower/call.iyi" \
  "    alloca_local(low, vars, arg.name, arg_types[i])" "    alloca_local(low, vars, arg.name, low.analysed.program.nil_type)" -- lower_calls_check || status=1
prove_mutation "a block branch's value is merged as the last branch" "$REPO/src/compiler/lower/block.iyi" \
  "  phi.add_branch(low, value, false)" "  phi.add_branch(low, value, true)" -- lower_calls_check || status=1
prove_mutation "a block branch's value is dropped" "$REPO/src/compiler/lower/block.iyi" \
  "      value = v.as(Value)" "      value = nil" -- lower_calls_check || status=1
prove_mutation "a break from a block drops its value" "$REPO/src/compiler/lower/lower.iyi" \
  "    branch_to_phi(low, block_phi.as(BranchPhi), node.exp, jump_target(node, low.current_context.break_target))" "    branch_to_phi(low, block_phi.as(BranchPhi), nil, jump_target(node, low.current_context.break_target))" -- lower_calls_check || status=1
prove_mutation "a return from an inlined def drops its value" "$REPO/src/compiler/lower/lower.iyi" \
  "    branch_to_phi(low, rp.as(BranchPhi), node.exp, jump_target(node, low.current_context.return_target))" "    branch_to_phi(low, rp.as(BranchPhi), nil, jump_target(node, low.current_context.return_target))" -- lower_calls_check || status=1
prove_mutation "a method's receiver is not passed to the call" "$REPO/src/compiler/lower/call.iyi" \
  "    out << sv.as(Value)" "    out.size" -- lower_calls_check || status=1
prove_mutation "a method's mangled name has no owner" "$REPO/src/compiler/lower/fun.iyi" \
  'text = text + owner_segment(st, name, false) + "#"' 'text = text + "#"' -- lower_calls_check || status=1
prove_mutation "a block call does not bind self in the inlined def" "$REPO/src/compiler/lower/call.iyi" \
  '      frame.vars["self"] = LowerVar.new(sv.as(Value), st, !self_by_pointer?(st))' '      frame.vars.size' -- lower_calls_check || status=1
prove_mutation "a method's self is not the first parameter" "$REPO/src/compiler/lower/fun.iyi" \
  '    first = 1' '    first = 0' -- lower_calls_check || status=1
prove_mutation "a lib call passes no arguments" "$REPO/src/compiler/lower/call.iyi" \
  'inst = low.builder.call(fn_type, func.as(Function), values, "")' 'inst = low.builder.call(fn_type, func.as(Function), [] of Value, "")' -- lower_calls_check || status=1
prove_mutation "a lib fun is declared with the iyi calling convention" "$REPO/src/compiler/lower/call.iyi" \
  'made = low.module.add_function(real, fn_type, CallConv::C)' 'made = low.module.add_function(real, fn_type, CallConv::Iyi)' -- lower_calls_check || status=1
prove_mutation "a lib call's function type returns nil" "$REPO/src/compiler/lower/call.iyi" \
  'fn_type = low.module.types.func(params, low.typer.llvm_return_type(ret), lib_fun.varargs?)' 'fn_type = low.module.types.func(params, low.typer.llvm_return_type(low.analysed.program.nil_type), lib_fun.varargs?)' -- lower_calls_check || status=1
prove_mutation "a lib call's result is declared as an integer (a pointer result is caught)" "$REPO/src/compiler/lower/call.iyi" \
  'fn_type = low.module.types.func(params, low.typer.llvm_return_type(ret), lib_fun.varargs?)' 'fn_type = low.module.types.func(params, low.module.types.int32, lib_fun.varargs?)' -- lower_calls_check || status=1
prove_mutation "a class method is named with the instance separator (# not ::)" "$REPO/src/compiler/lower/fun.iyi" \
  'text = text + owner_segment(co, name, true) + "::"' 'text = text + owner_segment(co, name, true) + "#"' -- lower_calls_check || status=1
prove_mutation "a stored struct receiver is loaded, not passed by its address" "$REPO/src/compiler/lower/call.iyi" \
  'return nil if lv.already_loaded' 'return nil if true' -- lower_calls_check || status=1
prove_mutation "an empty (Nop) body is not inlined" "$REPO/src/compiler/lower/call.iyi" \
  'body.is_a?(Nop) || body.is_a?(NilLiteral)' 'body.is_a?(NilLiteral)' -- lower_calls_check || status=1
prove_mutation "a def is emitted with the C calling convention (a struct result is then refused)" "$REPO/src/compiler/lower/fun.iyi" \
  'return CallConv::Iyi if name.starts_with?("*")' 'return CallConv::C if name.starts_with?("*")' -- lower_calls_check || status=1
prove_mutation "a struct call result is returned as the aggregate, not its spill address (hosted call.cr:707-713)" "$REPO/src/compiler/lower/call.iyi" \
  '        low.last = temp' '        low.last = inst' -- lower_calls_check || status=1
prove_mutation "a module-level build constant is kept in the module (the module check catches it)" "$REPO/bench/lib/lower_gate.iyi" \
  'next if stripped.starts_with?("@") && build_constant?(stripped, builds) || stripped.starts_with?("%Nil = type")' 'next if stripped.starts_with?("%Nil = type")' -- lower_calls_check || status=1
prove_mutation "a block body typed NoReturn is refused (no hosted upcast applies to a body that never returns)" "$REPO/src/compiler/lower/call.iyi" \
  'body_no_return = body_t.as(Type).is_a?(NoReturnType)' 'body_no_return = false' -- lower_calls_check || status=1
prove_mutation "a top-level fun with a body is emitted with the iyi calling convention" "$REPO/src/compiler/lower/fun.iyi" \
  "  CallConv::C
end" "  CallConv::Iyi
end" -- lower_calls_check || status=1
prove_mutation "an instantiated generic parameter is resolved in program scope" "$REPO/src/compiler/lower/call.iyi" \
  '    param_type = low.analysed.type_of?(def_node.args[i])' '    param_type = def_node.args[i].restriction ? low.analysed.program.lookup_type_node(def_node.args[i].restriction.as(ASTNode), low.analysed.program) : low.analysed.type_of?(def_node.args[i])' -- lower_calls_check || status=1
prove_mutation "generic allocation skips preparing its metaclass receiver" "$REPO/src/compiler/lower/call.iyi" \
  '      type_id_value(low, inst) if inst.is_a?(GenericClassInstanceMetaclassType)' '      type_id_value(low, inst) if false' -- lower_calls_check || status=1
prove_mutation "a computed metaclass receiver is not evaluated" "$REPO/src/compiler/lower/call.iyi" \
  '      unless node.obj.as(ASTNode).is_a?(Path)' '      if false' -- lower_calls_check || status=1
prove_mutation "an inherited call loses its defining owner" "$REPO/src/compiler/lower/call.iyi" \
  '    if defining = low.analysed.program.def_owner(target)' '    if defining = nil' -- lower_calls_check || status=1
prove_mutation "a nil argument is passed as the visit left it, not as the nil value (hosted zeroinitializer)" "$REPO/src/compiler/lower/call.iyi" \
  'passed = at.is_a?(NilType) ? low.builder.const_zero(low.typer.nil_type).as(Value) : value.as(Value)' 'passed = value.as(Value)' -- lower_calls_check || status=1
prove_mutation "an unqualified class-method call loses its class owner" "$REPO/src/compiler/lower/call.iyi" \
  '          class_owner = ct' '          class_owner = nil' -- lower_calls_check || status=1
prove_mutation "a generic metaclass call passes no self type id" "$REPO/src/compiler/lower/call.iyi" \
  '      self_value = type_id_value(low, recv_type)' '      self_value = nil' -- lower_calls_check || status=1
prove_mutation "a builtin metaclass receiver is refused" "$REPO/src/compiler/lower/call.iyi" \
  '    unless (inst.is_a?(NonGenericClassType) || inst.is_a?(NonGenericModuleType)) && !inst.is_a?(NilType)' '    unless (inst.is_a?(NonGenericClassType) || inst.is_a?(NonGenericModuleType)) && !inst.is_a?(NilType) && primitive_kind(inst) == ""' -- lower_calls_check || status=1
prove_mutation "an implicit builtin class call is refused" "$REPO/src/compiler/lower/call.iyi" \
  '      if (ct.is_a?(NonGenericClassType) || ct.is_a?(NonGenericModuleType)) && !ct.is_a?(NilType)' '      if (ct.is_a?(NonGenericClassType) || ct.is_a?(NonGenericModuleType)) && !ct.is_a?(NilType) && primitive_kind(ct) == ""' -- lower_calls_check || status=1
prove_mutation "a computed metaclass receiver is not evaluated" "$REPO/src/compiler/lower/call.iyi" \
  '      unless node.obj.as(ASTNode).is_a?(Path)' '      if false' -- lower_calls_check || status=1
prove_mutation "a captured block precedes self in the call" "$REPO/src/compiler/lower/call.iyi" \
  '      emit_def_call(low, node, func, self_value, values, ret)' '      emit_def_call(low, node, func, nil, call_arguments(self_value, values).reverse, ret)' -- lower_calls_check || status=1

echo
if [ "$status" -eq 0 ]; then
  echo "lowering of calls and functions: all checks hold"
else
  echo "lowering of calls and functions: FAILED (see above)"
fi
exit "$status"
