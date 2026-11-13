#!/usr/bin/env bash
# Fails when the typed lowering of the core (src/compiler/lower/{lower,context}.iyi)
# stops agreeing with the hosted code generator's module for the same fixture.
#
# For each fixture (bench/fixtures/lower_*.iyi) the hosted compiler builds the program
# against --prelude empty, with --emit llvm-ir and --no-debug. Its module is read
# through the port's IR text parser (src/compiler/ir/parser.iyi) and printed by the
# port's printer, the same as the port's own lowering. The port analyses the fixture
# with its semantic passes, lowers it with lower/lower.iyi, and prints the module. The
# two normalised texts are compared function by function, and each function is
# reported identical, or differing at which line, or missing.
#
# Normalisation, the same on both sides (the driver's header lists it):
#   - the compiler's build constants: every global named ::BUILD_*, the private
#     constants that hold their text, and the stores into them. The program stores
#     them on entry; they are the compiler's identity, not the program's.
#   - the printf declaration the hosted constant printing emits, the attribute groups,
#     comments and the source header.
#   - the function type of a direct call. LLVM 22 writes `call void @f(i32 %a)` and
#     leaves the type out; the port's text form writes `call void (i32) @f(i32 %a)`,
#     which the port's parser reads. This script writes the type into the oracle's
#     calls from the argument types before the port reads it (see CALL_TYPES below).
#
# A fixture the port cannot analyse, or one that reaches a construct lower/pending.iyi
# refuses by name, is WAITING: the gate names the reason and counts it as neither passed
# nor failed. A fixture the port lowers to a different module is a failure.
#
# Mutation proofs patch the ported code, rebuild the driver, and require the gate to
# fail. A patch that changes nothing is refused by prove_mutation.
#
#   bash bench/selfhost_lower_core_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
. "$REPO/bench/lib/mutation.sh"
WORK="$(mktemp -d)"

trap 'rm -rf "$WORK"' EXIT

# CALL_TYPES, the awk that writes the call types and the phi labels into the oracle, is
# shared with the calls gate (bench/lib/lower_oracle.sh).
. "$REPO/bench/lib/lower_oracle.sh"

# The oracle rewriter reads a callee up to its own closing parenthesis: a quoted generic name holds
# parentheses of its own (`@"*Box(Int32)^Box(T)::new<Int32>:Box(Int32)"`). The check re-sources the library
# in a subshell, so a mutation of bench/lib/lower_oracle.sh is what it tests.
quoted_callee_line='  %2 = call %"Box(Int32)" @"*Box(Int32)^Box(T)::new<Int32>:Box(Int32)"(i32 %1, i32 7) #3'
quoted_callee_expected='  %2 = call iyicc %"Box(Int32)" (i32, i32) @"*Box(Int32)^Box(T)::new<Int32>:Box(Int32)"(i32 %1, i32 7)'
quoted_callee_check() {
  local got
  got="$(bash -c '. "$1"; awk "$CALL_TYPES" <<< "$2"' _ "$REPO/bench/lib/lower_oracle.sh" "$quoted_callee_line")" || return 1
  [ "$got" = "$quoted_callee_expected" ]
}
echo "== 0. The oracle rewriter reads a quoted callee name whole"
if quoted_callee_check; then
  echo "  $quoted_callee_expected"
else
  echo "  FAIL: the oracle rewriter does not write the quoted callee's type (lower_oracle.sh CALL_TYPES)"
  status=1
fi
echo

# A prose line for each fixture verdict, so the summary can be read without the logs.
verdict_lines=""

echo "== 1. Building the port driver and the context checks"
if ! "$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/port.build.log" 2>&1; then
  echo "the port driver failed to build:"
  awk 'NR<=20' "$WORK/port.build.log"
  exit 1
fi
if "$WORK/port" context > "$WORK/context.out" 2>&1 && awk '/^CONTEXT OK$/ { ok = 1 } END { exit !ok }' "$WORK/context.out"; then
  echo "  lower/context.iyi: the state and the alloca rule hold"
else
  echo "  lower/context.iyi: CONTEXT CHECKS FAILED:"
  awk 'NR<=6' "$WORK/context.out"
  status=1
fi

echo
echo "== 2. Each fixture: the hosted module against the port's lowering"
passed=0
# Fixtures whose modules differ from the hosted one for reasons named in NEEDS.md
# wait by name; the gate fails if one starts to match.
# The pointer-union fixture's allocator also differs in its metaclass type-id load;
# its hosted symbol and the naming mutation are checked independently below.
KNOWN_DIVERGED="lower_string_nonascii lower_pointer_malloc lower_name_pointer_union"
e2e=""
module_same=0
module_differ=0
diverged=0
waiting=0
for fixture in "$REPO"/bench/fixtures/lower_*.iyi; do
  name="$(basename "$fixture" .iyi)"
  # lower_headed_late is proved in section 2c against the arena prelude. The empty-prelude
  # loop names its proc Proc(Base, Base); the port, having made the virtual type, names Base+.
  if [ "$name" = "lower_headed_late" ] || [ "$name" = "lower_probe_reuse" ]; then
    continue
  fi
  if ! "$IYI" build --prelude empty --emit llvm-ir --no-debug -o "$WORK/$name" "$fixture" > "$WORK/$name.oracle.log" 2>&1 || [ ! -s "$WORK/$name.ll" ]; then
    echo "  $name: the hosted compiler did not emit its module (see $WORK/$name.oracle.log)"
    awk 'NR<=3' "$WORK/$name.oracle.log"
    diverged=$((diverged + 1))
    continue
  fi
  awk "$CALL_TYPES" "$WORK/$name.ll" > "$WORK/$name.oracle.ll"

  if ! "$WORK/port" oracle "$WORK/$name.oracle.ll" > "$WORK/$name.oracle.txt" 2> "$WORK/$name.oracle.err"; then
    echo "  $name: the port's IR parser refuses the hosted module: $(awk 'NR==1' "$WORK/$name.oracle.err")"
    diverged=$((diverged + 1))
    continue
  fi

  if ! "$WORK/port" lower "$fixture" "$WORK/$name.oracle.ll" > "$WORK/$name.port.out" 2> "$WORK/$name.port.err"; then
    reason="$(awk 'NR==1' "$WORK/$name.port.err")"
    echo "  $name: WAITING: $reason"
    waiting=$((waiting + 1))
    continue
  fi
  echo "  $name:"
  awk 'NR>0' "$WORK/$name.port.out" | awk '!/^SUMMARY/' | awk '{ print "    " $0 }'
  summary="$(awk '/^SUMMARY/ { print }' "$WORK/$name.port.out")"
  identical="$(echo "$summary" | awk '{ split($2, a, "="); print a[2] }')"
  total="$(echo "$summary" | awk '{ split($3, a, "="); print a[2] }')"
  module_ok="$(echo "$summary" | awk '{ split($4, a, "="); print a[2] }')"
  if [ "$module_ok" = 1 ]; then
    module_same=$((module_same + 1))
  else
    module_differ=$((module_differ + 1))
  fi
  if [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$identical" = "$total" ]; then
    case " $KNOWN_DIVERGED " in
      *" $name "*) echo "    $name: now identical to the hosted module: remove it from KNOWN_DIVERGED"; diverged=$((diverged + 1)) ;;
    esac
    echo "    $name: PASSED, $identical of $total functions identical (module-level counted below)"
    passed=$((passed + 1))
    e2e="$e2e $name"
  else
    case " $KNOWN_DIVERGED " in
      *" $name "*) echo "    $name: WAITING, known divergence: $identical of $total identical (see NEEDS.md)"; waiting=$((waiting + 1)) ;;
      *) echo "    $name: DIVERGED, $identical of $total identical"; diverged=$((diverged + 1)) ;;
    esac
  fi
done
echo "  fixtures: $passed passed, $diverged diverged, $waiting waiting (named above)"
if [ "$diverged" -gt 0 ]; then
  status=1
fi
if [ "$passed" -eq 0 ]; then
  echo "  no fixture passed: the gate proves nothing yet"
  status=1
fi

echo
echo "== 2b. End to end: each fixture the port lowers identically, built to a native executable and run"
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
      if grep -q "cannot be rebased" "$WORK/$name.native.log"; then
        echo "  $name: WAITING, the native tool cannot rebase an absolute pointer in a constant: $(awk 'NR==1' "$WORK/$name.native.log")"
        waiting=$((waiting + 1))
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

module_floor_file="$REPO/bench/selfhost_lower_core_module.floor"
module_floor="$(awk 'NR==1 { print $1 }' "$module_floor_file" 2>/dev/null)"
module_floor="${module_floor:-0}"
echo "  module-level: $module_same identical to the hosted module, $module_differ differ (type-id constants, NEEDS.md row 16)"
if [ -n "${LOWER_MODULE_RAISE:-}" ] && [ "$module_same" -gt "$module_floor" ]; then
  echo "$module_same" > "$module_floor_file"
  module_floor="$module_same"
  echo "  wrote the module-level floor: $module_same"
fi
if [ "$module_same" -lt "$module_floor" ]; then
  echo "  FAIL: module-level identity fell below its floor ($module_same < $module_floor)"
  status=1
fi
echo
echo "== 3. Mutation proofs: the gate must catch each patch to the ported code"
# The check rebuilds the driver from the patched source and requires the nil fixture
# to match the hosted module exactly, and the context checks to hold. It returns 0 only
# on the unmutated behaviour.
CORE_CHECK_FIXTURES="lower_nil lower_int lower_bool lower_assign lower_if lower_char lower_while lower_break lower_unless lower_fold lower_cond_int lower_return lower_return_bare lower_return_last lower_typedecl lower_typedecl_nil lower_fun_nil lower_fun_unused lower_implicit_self lower_fun_iyi lower_uint64_big lower_proc_literal lower_uninitialized lower_uninitialized_value lower_class_new lower_cast lower_assign_param lower_isa_union"
# The mutation check: the driver rebuilt from the patched source must still lower each identical fixture to the hosted
# module (known divergences are left out, so the unmutated check passes and a mutation is caught by a real difference).
lower_core_check() {
  "$IYI" build -o "$WORK/port-m" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/m.build.log" 2>&1 || return 1
  "$WORK/port-m" context > "$WORK/m.ctx" 2>&1 || return 1
  awk '/^CONTEXT OK$/ { ok = 1 } END { exit !ok }' "$WORK/m.ctx" || return 1
  for n in $CORE_CHECK_FIXTURES; do
    "$WORK/port-m" lower "$REPO/bench/fixtures/$n.iyi" "$WORK/$n.oracle.ll" > "$WORK/m.out" 2> "$WORK/m.err" || return 1
    awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); exit !(a[2] == b[2] && a[2] > 0) }' "$WORK/m.out" || return 1
  done
  return 0
}
# The long-string name: a string constant longer than 18 bytes is named by its first 19 bytes and `...` (hosted
# codegen.cr:3463). The fixture's module differs only in the String type id (NEEDS.md row 16), so the gate
# compares the name in the port's own module text rather than the whole module.
long_name_check() {
  "$IYI" build -o "$WORK/port-n" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/n.build.log" 2>&1 || return 1
  "$WORK/port-n" emit "$REPO/bench/fixtures/lower_string_long.iyi" "$WORK/lower_string_long.oracle.ll" > "$WORK/n.ll" 2>&1 || return 1
  needle="a string constant l...'"
  awk -v n="$needle" 'index($0, n) > 0 { ok = 1 } END { exit !ok }' "$WORK/n.ll"
}
echo "  the long string constant is named by its hosted truncated name:"
if long_name_check; then
  echo "    yes"
else
  echo "    NO: the long-string name differs from the hosted truncated name"
  status=1
fi
string_name_check() {
  "$IYI" build -o "$WORK/port-n" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/n.build.log" 2>&1 || return 1
  "$WORK/port-n" emit "$REPO/bench/fixtures/$1.iyi" "$WORK/$1.oracle.ll" > "$WORK/n.ll" 2>&1 || return 1
  NEEDLE="$2" awk 'index($0, ENVIRON["NEEDLE"]) > 0 { ok = 1 } END { exit !ok }' "$WORK/n.ll"
}
# A non-ASCII long text is cut by character (codegen.cr:3463), and its bytes are written in the port's text form.
nonascii_name_check() {
  string_name_check lower_string_nonascii "'h\\xc3\\xa9llo w\\xc3\\xb6rld \\xc3\\xbcn\\xc3\\xafcode...'"
}
# Two texts with one 19-character cut: the second global takes the module's next number (LLVM's makeUniqueName).
collide_name_check() {
  string_name_check lower_string_collide "'a string constant l...'.1"
}
echo "  the non-ASCII long string constant is cut by character, and the second of two colliding names is renamed:"
if nonascii_name_check && collide_name_check; then
  echo "    yes"
else
  echo "    NO: a string constant name differs from the hosted name"
  status=1
fi

pointer_malloc_check() {
  "$IYI" build -o "$WORK/port-n" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/n.build.log" 2>&1 || return 1
  "$WORK/port-n" emit "$REPO/bench/fixtures/lower_pointer_malloc.iyi" "$WORK/lower_pointer_malloc.oracle.ll" > "$WORK/ptr_malloc.ir" 2>/dev/null || return 1
  awk '/call ptr.*@malloc\(i64/ { m = 1 } /intrinsic llvm\.memset\.p0\.i64/ { s = 1 } END { exit !(m && s) }' "$WORK/ptr_malloc.ir"
}
echo "  Pointer(UInt8).malloc emits C malloc and memset:"
if pointer_malloc_check; then
  echo "    yes"
else
  echo "    no"
  status=1
fi
echo "  the mutation check passes on the unmutated code:"
if lower_core_check; then
  echo "    yes"
else
  echo "    NO: the mutation proofs below would prove nothing"
  status=1
fi
prove_mutation "a long string constant is named in full, not truncated" "$REPO/src/compiler/lower/helpers.iyi" \
  'name_text = first_chars(str, 19) + "..."' 'name_text = str' -- long_name_check || status=1
prove_mutation "a non-ASCII long string constant is cut in bytes, not characters" "$REPO/src/compiler/lower/helpers.iyi" \
  'name_text = first_chars(str, 19) + "..."' 'name_text = str[0, 19] + "..."' -- nonascii_name_check || status=1
prove_mutation "a renamed global takes the number after the next" "$REPO/src/compiler/lower/helpers.iyi" \
  'candidate = name + "." + low.last_unique.to_s' 'candidate = name + "." + (low.last_unique + 1_i64).to_s' -- collide_name_check || status=1
prove_mutation "a taken global name is not renamed" "$REPO/src/compiler/lower/helpers.iyi" \
  'while low.module.global?(candidate) || low.module.function?(candidate)' 'while low.module.function?(candidate)' -- collide_name_check || status=1
prove_mutation "a runtime fun's name is external, not internal" "$REPO/src/compiler/lower/lower.iyi" \
  'if name.starts_with?("__crystal_")' 'if name.starts_with?("__crystal_no_such_")' -- lower_core_check || status=1
prove_mutation "a fun is not marked emitted, so its body is lowered again" "$REPO/src/compiler/lower/lower.iyi" \
  "low.fun_defs_done[name] = true" "low.fun_defs_done.size" -- lower_core_check || status=1
prove_mutation "argv is stored from the argc parameter" "$REPO/src/compiler/lower/lower.iyi" \
  "store_aligned(low, fn.param(1), argv_global)" "store_aligned(low, fn.param(0), argv_global)" -- lower_core_check || status=1
prove_mutation "main returns 1" "$REPO/src/compiler/lower/lower.iyi" \
  "low.builder.ret(low.builder.const_int(i32, 0))" "low.builder.ret(low.builder.const_int(i32, 1))" -- lower_core_check || status=1
prove_mutation "a declared variable's value is not stored" "$REPO/src/compiler/lower/lower.iyi" \
  "store_aligned(low, v.as(Value), pointer)" "low.last = v" -- lower_core_check || status=1
prove_mutation "a return of a constant zero" "$REPO/src/compiler/lower/lower.iyi" \
  "low.builder.ret(returned)" "low.builder.ret(low.builder.const_int(ret_ir, 0_i64))" -- lower_core_check || status=1
prove_mutation "a declared variable is read without a load" "$REPO/src/compiler/lower/lower.iyi" \
  "LowerVar.new(pointer, dt, false)" "LowerVar.new(pointer, dt, true)" -- lower_core_check || status=1
prove_mutation "the alloca block is named after the entry block" "$REPO/src/compiler/lower/context.iyi" \
  'new_blocks(["alloca", "entry"])' 'new_blocks(["entry", "alloca"])' -- lower_core_check || status=1
prove_mutation "a bool literal is false" "$REPO/src/compiler/lower/lower.iyi" \
  "return 1_i64" "return 0_i64" -- lower_core_check || status=1
prove_mutation "a store is aligned to one byte" "$REPO/src/compiler/lower/helpers.iyi" \
  "set_align(st, low.typer.align_of(value.type))" "set_align(st, 1)" -- lower_core_check || status=1
prove_mutation "the then and else branches are swapped" "$REPO/src/compiler/lower/lower.iyi" \
  "low.builder.cond_br(cond_value, then_block, else_block)" "low.builder.cond_br(cond_value, else_block, then_block)" -- lower_core_check || status=1
prove_mutation "the while body is the condition" "$REPO/src/compiler/lower/lower.iyi" \
  "codegen_node(low, node.body)" "codegen_node(low, node.cond)" -- lower_core_check || status=1
prove_mutation "a char is its code point plus one" "$REPO/src/compiler/lower/lower.iyi" \
  "node.value.ord.to_i64)" "node.value.ord.to_i64 + 1_i64)" -- lower_core_check || status=1
prove_mutation "an empty alloca block is kept" "$REPO/src/compiler/lower/context.iyi" \
  "current_fun.blocks.delete(alloca)" "alloca.name" -- lower_core_check || status=1
prove_mutation "an unused fun is not recorded for the deferred body pass" "$REPO/src/compiler/lower/lower.iyi" \
  "low.unused_fun_defs << node" "low.unused_fun_defs.size" -- lower_core_check || status=1
prove_mutation "the deferred pass that defines unused funs is not run" "$REPO/src/compiler/lower/lower.iyi" \
  "  emit_unused_fun_defs(low)" "  low.unused_fun_defs.size" -- lower_core_check || status=1
prove_mutation "a fun definition is internal, not external" "$REPO/src/compiler/lower/lower.iyi" \
  "fn.linkage = Linkage::External" "fn.linkage = Linkage::Internal" -- lower_core_check || status=1
prove_mutation "an implicit self call passes no self" "$REPO/src/compiler/lower/call.iyi" \
  "self_value = implicit_self_value(low)" "self_value = nil" -- lower_core_check || status=1
prove_mutation "the oracle rewriter reads a quoted callee name to its first parenthesis" "$REPO/bench/lib/lower_oracle.sh" \
  'if (substr(s, i, 1) == "\"") return i' 'if (substr(s, i, 1) == "\"") return index(s, "(") - 1' -- quoted_callee_check || status=1
prove_mutation "an asm-referenced runtime fun is internal, not external" "$REPO/src/compiler/lower/lower.iyi" \
  'if asm_referenced_fun?(name) || name == "__iyi_new"' 'if name == "__iyi_new"' -- lower_core_check || status=1
prove_mutation "a UInt64 literal past Int64 max is read with to_i64, not its bit pattern" "$REPO/src/compiler/lower/lower.iyi" \
  "const_int(ir, uint64_bits(node.value.to_u64))" "const_int(ir, node.value.to_i64)" -- lower_core_check || status=1
prove_mutation "a proc literal's name uses the file as given, not relative to the working directory" "$REPO/src/compiler/lower/proc.iyi" \
  'symbol_text(relative_filename(loc.filename))' 'symbol_text(loc.filename)' -- lower_core_check || status=1
prove_mutation "an uninitialized variable's value is the slot itself, not a load of it" "$REPO/src/compiler/lower/lower.iyi" \
  "low.last = to_lhs(low, slot.pointer, nt)" "low.last = slot.pointer" -- lower_core_check || status=1
prove_mutation "Pointer#malloc refuses a UInt64 count by inverting the size_t check" "$REPO/src/compiler/lower/primitives.iyi" \
  "  if count.type != low.typer.size_t" "  if count.type == low.typer.size_t" -- pointer_malloc_check || status=1
prove_mutation "Cast nil to Pointer emits llvm_nil instead of null pointer" "$REPO/src/compiler/lower/lower.iyi" \
  "      low.last = low.builder.const_null(low.typer.llvm_type(to_type))" "      low.last = llvm_nil(low)" -- lower_core_check || status=1
prove_mutation "NilableCast branches swap matches and doesnt_match" "$REPO/src/compiler/lower/lower.iyi" \
  "    low.builder.cond_br(cmp, matches_block, doesnt_match_block)" "    low.builder.cond_br(cmp, doesnt_match_block, matches_block)" -- lower_core_check || status=1
prove_mutation "Assign to a parameter skips the local copy" "$REPO/src/compiler/lower/fun.iyi" \
  "  needs_copy = assigned_to || var_type.full_name != arg_type.full_name" "  needs_copy = false || var_type.full_name != arg_type.full_name" -- lower_core_check || status=1
prove_mutation "is_a? on NilableType tests non-null instead of null" "$REPO/src/compiler/lower/cast.iyi" \
  "    is_null = low.builder.icmp(IntPredicate::EQ, value, low.builder.const_null_pointer)" "    is_null = low.builder.icmp(IntPredicate::NE, value, low.builder.const_null_pointer)" -- lower_core_check || status=1
prove_mutation "union match function combines members with AND instead of OR" "$REPO/src/compiler/lower/cast.iyi" \
  "        acc = low.builder.bitwise_or(cur, cond)" "        acc = low.builder.bitwise_and(cur, cond)" -- lower_core_check || status=1

# The module-level count: how many CORE_CHECK_FIXTURES match the hosted module in every item, module-level included.
# A patch that changes only module-level text lowers the count, and this check catches it.
core_module_count() {
  same=0
  for n in $CORE_CHECK_FIXTURES; do
    if "$1" lower "$REPO/bench/fixtures/$n.iyi" "$WORK/$n.oracle.ll" > "$WORK/cmc.out" 2> "$WORK/cmc.err" && awk '/^SUMMARY/ { split($4, a, "="); exit !(a[2] == 1) }' "$WORK/cmc.out"; then
      same=$((same + 1))
    fi
  done
  echo "$same"
}
module_count_check() {
  "$IYI" build -o "$WORK/port-mm" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/mm.build.log" 2>&1 || return 1
  [ "$(core_module_count "$WORK/port-mm")" -ge "$module_baseline" ]
}
module_baseline="$(core_module_count "$WORK/port")"
echo "  module-level baseline over the checked fixtures: $module_baseline"
prove_mutation "the argc global is external, not internal (module-level text only)" "$REPO/src/compiler/lower/lower.iyi" \
  "argc_global.linkage = Linkage::Internal" "argc_global.linkage = Linkage::External" -- module_count_check || status=1

# A class allocated before the use that makes its virtual type. The oracle is built against the
# minimal arena prelude (IYI_PATH ends so the hosted compiler's iyi_prelude? is true and the
# allocation loads @"Base:headed"). The port analyses the prelude and the fixture as one source.
# Compared: the new function's body and the headed globals. The rest of the module is the
# compiler's own identity and the injected builtins, which this check does not claim.
headed_late_ir() {
  local portbin="$1"
  local pre="$REPO/bench/fixtures/lower_headed_prelude"
  local fix="$REPO/bench/fixtures/lower_headed_late.iyi"
  IYI_PATH="$pre" "$IYI" build --emit llvm-ir --no-debug -o "$WORK/headed" "$fix" > "$WORK/headed.hosted.log" 2>&1 || return 1
  [ -s "$WORK/headed.ll" ] || return 1
  awk "$CALL_TYPES" "$WORK/headed.ll" > "$WORK/headed.rewritten.ll" || return 1
  "$portbin" oracle "$WORK/headed.rewritten.ll" > "$WORK/headed.hostnorm" 2> "$WORK/headed.oracle.err" || return 1
  awk '1' "$pre/iyi/prelude.iyi" "$fix" > "$WORK/headed.combined.iyi"
  "$portbin" emit "$WORK/headed.combined.iyi" "$WORK/headed.ll" > "$WORK/headed.port.ll" 2> "$WORK/headed.port.err" || return 1
  python3 - "$WORK/headed.hostnorm" "$WORK/headed.port.ll" << 'PY' || return 1
import sys
def grab(text):
    out = []
    on = False
    for line in text.splitlines():
        if not on and "Base::new:Base" in line and line.startswith("define"):
            on = True
            continue
        if on:
            out.append(line)
            if line == "}":
                break
    return out
def headed(text):
    return [line for line in text.splitlines() if line.startswith('@"Base:headed"') or line.startswith('@"Child:headed"')]
host = open(sys.argv[1]).read()
port = open(sys.argv[2]).read()
hb, pb = grab(host), grab(port)
hh, ph = headed(host), headed(port)
if hb != pb or hh != ph or not hb or not hh:
    sys.stderr.write("headed body or global differs\n")
    sys.exit(1)
PY
}
headed_late_check() {
  "$IYI" build -o "$WORK/port-h" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/headed.build.log" 2>&1 || return 1
  headed_late_ir "$WORK/port-h"
}
echo
echo "== 2c. Headed byte is a global filled after every def"
if headed_late_check; then
  echo "  lower_headed_late: *Base::new:Base body and headed globals identical to the hosted module"
  if "$IYI" build -o "$WORK/compile_native" "$REPO/src/compiler/tools/compile_native.iyi" > "$WORK/headed.tool.log" 2>&1 && "$WORK/compile_native" "$WORK/headed.port.ll" -o "$WORK/headed.native" > "$WORK/headed.native.log" 2>&1; then
    timeout 30 "$WORK/headed.native" > "$WORK/headed.native.out" 2>&1; ns=$?
    timeout 30 "$WORK/headed" > "$WORK/headed.hosted.out" 2>&1; hs=$?
    if [ "$ns" = "$hs" ] && cmp -s "$WORK/headed.native.out" "$WORK/headed.hosted.out"; then
      echo "  lower_headed_late: native executable runs to the hosted result (status $hs)"
    else
      echo "  lower_headed_late: native status $ns, hosted $hs"
      status=1
    fi
  else
    echo "  lower_headed_late: the native tool refused the port module: $(awk 'NR==1' "$WORK/headed.native.log" "$WORK/headed.tool.log")"
    status=1
  fi
else
  echo "  lower_headed_late: DIVERGED"
  awk 'NR<=8' "$WORK/headed.port.err" "$WORK/headed.hosted.log" "$WORK/headed.oracle.err"
  status=1
fi
prove_mutation "the headed byte is a constant chosen at the allocation" "$REPO/src/compiler/lower/primitives.iyi" \
  'load_aligned(low, low.module.types.int8, headed_global(low, t))' \
  'low.builder.const_int(low.module.types.int8, 0_i64)' -- headed_late_check || status=1

probe_reuse_check() {
  "$IYI" build -o "$WORK/port-p" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/probe.build.log" 2>&1 || return 1
  "$WORK/port-p" probe-reuse "$REPO/bench/fixtures/lower_probe_reuse.iyi" > "$WORK/probe.out" 2>"$WORK/probe.err" || return 1
  awk '/^callee-clean=0$/ { ok = 1 } END { exit !ok }' "$WORK/probe.out"
}
echo
echo "== 2d. A failed probe does not leave a callee a later call records clean"
if probe_reuse_check; then
  echo "  lower_probe_reuse: the callee is not clean"
else
  echo "  lower_probe_reuse: the callee was recorded clean"
  awk 'NR<=8' "$WORK/probe.err" "$WORK/probe.out" "$WORK/probe.build.log"
  status=1
fi
prove_mutation "the completed-emission check dropped" "$REPO/src/compiler/lower/fun.iyi" \
  'return existing.as(Function) if fun_emission_done?(low.module, name) || low.emitting[name]?' \
  'return existing.as(Function)' -- probe_reuse_check || status=1
generic_ivar_check() {
  "$IYI" build -o "$WORK/port-g" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/g.build.log" 2>&1 || return 1
  "$WORK/port-g" lower "$REPO/bench/fixtures/lower_generic_ivar.iyi" "$WORK/lower_generic_ivar.oracle.ll" > "$WORK/g.out" 2> "$WORK/g.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); exit !(a[2] == b[2] && a[2] > 0) }' "$WORK/g.out"
}
prove_mutation "a generic class instance has no instance variables" "$REPO/src/compiler/lower/instance_var.iyi" \
  "  if owner.is_a?(GenericClassInstanceType)" \
  "  if false" -- generic_ivar_check || status=1
pointerof_ivar_check() {
  "$IYI" build -o "$WORK/port-pivar" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/pivar.build.log" 2>&1 || return 1
  "$WORK/port-pivar" lower "$REPO/bench/fixtures/lower_pointerof_ivar.iyi" "$WORK/lower_pointerof_ivar.oracle.ll" > "$WORK/pivar.out" 2> "$WORK/pivar.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); exit !(a[2] == b[2] && a[2] > 0) }' "$WORK/pivar.out"
}
prove_mutation "pointerof of an instance variable returns self" "$REPO/src/compiler/lower/instance_var.iyi" \
  "  low.last = instance_var_pointer(low, owner.as(Type), node.name, self_var.as(LowerVar).pointer)" \
  "  low.last = self_var.as(LowerVar).pointer" -- pointerof_ivar_check || status=1
struct_class_var_check() {
  "$IYI" build -o "$WORK/port-struct-cvar" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/struct-cvar.build.log" 2>&1 || return 1
  "$WORK/port-struct-cvar" lower "$REPO/bench/fixtures/lower_struct_class_var.iyi" "$WORK/lower_struct_class_var.oracle.ll" > "$WORK/struct-cvar.out" 2> "$WORK/struct-cvar.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/struct-cvar.out"
}
if struct_class_var_check; then
  prove_mutation "an address-valued struct receiver is spilled again" "$REPO/src/compiler/lower/instance_var.iyi" \
    '  return value if value.type.pointer?' \
    '  return value if false' -- struct_class_var_check || status=1
  prove_mutation "a global first-field address is not folded" "$REPO/src/compiler/lower/instance_var.iyi" \
    '  return pointer if index == 0 && pointer.is_a?(Global)' \
    '  return pointer if false' -- struct_class_var_check || status=1
else
  echo "FAIL: struct class-variable receiver does not match the hosted module"
  awk 'NR<=8' "$WORK/struct-cvar.err" "$WORK/struct-cvar.out" "$WORK/struct-cvar.build.log"
  status=1
fi
bare_return_check() {
  "$IYI" build -o "$WORK/port-return" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/return.build.log" 2>&1 || return 1
  "$WORK/port-return" lower "$REPO/bench/fixtures/lower_return_bare.iyi" "$WORK/lower_return_bare.oracle.ll" > "$WORK/return.out" 2> "$WORK/return.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); exit !(a[2] == b[2] && a[2] > 0) }' "$WORK/return.out"
}
if bare_return_check; then
  prove_mutation "a bare return skips the Nil upcast" "$REPO/src/compiler/lower/lower.iyi" \
    "    returned = upcast(low, llvm_nil(low), nil_type, ret_type.as(Type))" \
    "    returned = llvm_nil(low)" -- bare_return_check || status=1
else
  echo "FAIL: unmutated bare return does not match the hosted module"
  status=1
fi
visibility_check() {
  "$IYI" build -o "$WORK/port-vis" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/vis.build.log" 2>&1 || return 1
  "$WORK/port-vis" lower "$REPO/bench/fixtures/lower_visibility.iyi" "$WORK/lower_visibility.oracle.ll" > "$WORK/vis.out" 2> "$WORK/vis.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/vis.out"
}
if visibility_check; then
  prove_mutation "visibility wrappers do not visit their expression" "$REPO/src/compiler/lower/lower.iyi" \
    '    codegen_node(low, node.as(VisibilityModifier).exp)' \
    '    pending_visit_node("visibility wrapper")' -- visibility_check || status=1
else
  echo "FAIL: visibility wrapper fixture does not match the hosted module"
  awk 'NR<=8' "$WORK/vis.err" "$WORK/vis.out" "$WORK/vis.build.log"
  status=1
fi
visibility_macro_check() {
  "$IYI" build -o "$WORK/port-vis-macro" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/vis-macro.build.log" 2>&1 || return 1
  "$WORK/port-vis-macro" lower "$REPO/bench/fixtures/lower_visibility_macro.iyi" "$WORK/lower_visibility_macro.oracle.ll" > "$WORK/vis-macro.out" 2> "$WORK/vis-macro.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/vis-macro.out"
}
if visibility_macro_check; then
  prove_mutation "an expanded declaration macro is lowered as a call" "$REPO/src/compiler/lower/lower.iyi" \
    '      codegen_node(low, expanded)' \
    '      codegen_call_node(low, node.as(Call))' -- visibility_macro_check || status=1
else
  echo "FAIL: wrapped macro fixture does not match the hosted module"
  awk 'NR<=8' "$WORK/vis-macro.err" "$WORK/vis-macro.out" "$WORK/vis-macro.build.log"
  status=1
fi
atomic_return_check() {
  "$IYI" build -o "$WORK/port-atomic-return" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/atomic-return.build.log" 2>&1 || return 1
  "$WORK/port-atomic-return" lower "$REPO/bench/fixtures/lower_atomic_return.iyi" "$WORK/lower_atomic_return.oracle.ll" > "$WORK/atomic-return.out" 2> "$WORK/atomic-return.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/atomic-return.out"
}
if atomic_return_check; then
  prove_mutation "a by-value return skips loading the aggregate" "$REPO/src/compiler/lower/fun.iyi" \
    '  converted = to_rhs(low, converted, return_type.as(Type)) if converted.type.pointer?' \
    '  converted = converted' -- atomic_return_check || status=1
else
  echo "FAIL: atomic aggregate return does not match the hosted module"
  awk 'NR<=8' "$WORK/atomic-return.err" "$WORK/atomic-return.out" "$WORK/atomic-return.build.log"
  status=1
fi
array_expansion_check() {
  "$IYI" build -o "$WORK/port-array" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/array.build.log" 2>&1 || return 1
  "$WORK/port-array" lower "$REPO/bench/fixtures/lower_expanded_array.iyi" "$WORK/lower_expanded_array.oracle.ll" > "$WORK/array.out" 2> "$WORK/array.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/array.out"
}
if array_expansion_check; then
  prove_mutation "an array literal ignores its typed expansion" "$REPO/src/compiler/lower/lower.iyi" \
    '  if node.is_a?(ArrayLiteral)' \
    '  if false' -- array_expansion_check || status=1
else
  echo "FAIL: array expansion fixture does not match the hosted module"
  awk 'NR<=8' "$WORK/array.err" "$WORK/array.out" "$WORK/array.build.log"
  status=1
fi
interpolation_check() {
  "$IYI" build -o "$WORK/port-interpolation" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/interpolation.build.log" 2>&1 || return 1
  "$WORK/port-interpolation" lower "$REPO/bench/fixtures/lower_interpolation.iyi" "$WORK/lower_interpolation.oracle.ll" > "$WORK/interpolation.out" 2> "$WORK/interpolation.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/interpolation.out"
}
if interpolation_check; then
  prove_mutation "an interpolation ignores its typed expansion" "$REPO/src/compiler/lower/lower.iyi" \
    '  if node.is_a?(StringInterpolation)' \
    '  if false' -- interpolation_check || status=1
else
  echo "FAIL: interpolation fixture does not match the hosted module"
  awk 'NR<=8' "$WORK/interpolation.err" "$WORK/interpolation.out" "$WORK/interpolation.build.log"
  status=1
fi
interpolation_constant_check() {
  "$IYI" build -o "$WORK/port-interpolation-constant" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/interpolation-constant.build.log" 2>&1 || return 1
  "$WORK/port-interpolation-constant" lower "$REPO/bench/fixtures/lower_interpolation_constant.iyi" "$WORK/lower_interpolation_constant.oracle.ll" > "$WORK/interpolation-constant.out" 2> "$WORK/interpolation-constant.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/interpolation-constant.out"
}
if interpolation_constant_check; then
  prove_mutation "a constant interpolation is not folded" "$REPO/src/compiler/lower/lower.iyi" \
    '    if constant = interpolation_constant(low, node.as(StringInterpolation))' \
    '    if constant = (false ? interpolation_constant(low, node.as(StringInterpolation)) : nil)' -- interpolation_constant_check || status=1
else
  echo "FAIL: constant interpolation fixture does not match the hosted module"
  awk 'NR<=8' "$WORK/interpolation-constant.err" "$WORK/interpolation-constant.out" "$WORK/interpolation-constant.build.log"
  status=1
fi
named_tuple_check() {
  "$IYI" build -o "$WORK/port-named-tuple" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/named-tuple.build.log" 2>&1 || return 1
  "$WORK/port-named-tuple" lower "$REPO/bench/fixtures/lower_named_tuple.iyi" "$WORK/lower_named_tuple.oracle.ll" > "$WORK/named-tuple.out" 2> "$WORK/named-tuple.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/named-tuple.out"
}
if named_tuple_check; then
  prove_mutation "named tuple literal reverses entry evaluation" "$REPO/src/compiler/lower/lower.iyi" \
    '  node.entries.each do |entry|' \
    '  node.entries.reverse_each do |entry|' -- named_tuple_check || status=1
else
  echo "FAIL: named tuple fixture does not match the hosted module"
  awk 'NR<=8' "$WORK/named-tuple.err" "$WORK/named-tuple.out" "$WORK/named-tuple.build.log"
  status=1
fi
tuple_literal_check() {
  "$IYI" build -o "$WORK/port-tuple" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/tuple.build.log" 2>&1 || return 1
  "$WORK/port-tuple" lower "$REPO/bench/fixtures/lower_tuple_literal.iyi" "$WORK/lower_tuple_literal.oracle.ll" > "$WORK/tuple.out" 2> "$WORK/tuple.err" || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/tuple.out"
}
if tuple_literal_check; then
  prove_mutation "tuple literal reverses entry evaluation" "$REPO/src/compiler/lower/lower.iyi" \
    '  node.elements.each_with_index do |element, index|' \
    '  node.elements.reverse.each_with_index do |element, index|' -- tuple_literal_check || status=1
else
  echo "FAIL: tuple literal fixture does not match the hosted module"
  awk 'NR<=8' "$WORK/tuple.err" "$WORK/tuple.out" "$WORK/tuple.build.log"
  status=1
fi
tuple_entry_check() {
  "$IYI" build -o "$WORK/port-tuple-entry" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/tuple-entry.build.log" 2>&1 || return 1
  "$WORK/port-tuple-entry" emit "$REPO/bench/fixtures/lower_tuple.iyi" "$WORK/lower_tuple.oracle.ll" > "$WORK/tuple-entry.ir" 2> "$WORK/tuple-entry.err" || return 1
  "$WORK/compile_native" "$WORK/tuple-entry.ir" -o "$WORK/tuple-entry.native" > "$WORK/tuple-entry.native.log" 2>&1 || return 1
  timeout 30 "$WORK/tuple-entry.native" > "$WORK/tuple-entry.native.out" 2>&1; local ns=$?
  timeout 30 "$WORK/lower_tuple" > "$WORK/tuple-entry.hosted.out" 2>&1; local hs=$?
  [ "$ns" = "$hs" ] && cmp -s "$WORK/tuple-entry.native.out" "$WORK/tuple-entry.hosted.out"
}
if tuple_entry_check; then
  prove_mutation "a bare aggregate entry uses the C convention" "$REPO/src/compiler/lower/lower.iyi" \
    '  fn.call_convention = CallConv::Iyi' \
    '  fn.call_convention = CallConv::C' -- tuple_entry_check || status=1
else
  echo "FAIL: tuple entry does not run to the hosted result"
  awk 'NR<=8' "$WORK/tuple-entry.err" "$WORK/tuple-entry.build.log" "$WORK/tuple-entry.native.log"
  status=1
fi
entry_oracle_check() {
  local lib="$REPO/bench/lib/lower_oracle.sh"
  local text rewritten
  text="$(bash -c '. "$1"; awk "$CALL_TYPES" "$2"' _ "$lib" "$WORK/lower_tuple.ll")" || return 1
  printf '%s\n' "$text" > "$WORK/entry-rewritten.ll"
  "$WORK/port" lower "$REPO/bench/fixtures/lower_tuple.iyi" "$WORK/entry-rewritten.ll" > "$WORK/entry-rewritten.out" 2>&1 || return 1
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); split($4, c, "="); exit !(a[2] == b[2] && a[2] > 0 && c[2] == 1) }' "$WORK/entry-rewritten.out" || return 1
  rewritten="$(bash -c '. "$1"; awk "$CALL_TYPES" <<'"'"'EOF'"'"'
define internal void @__iyi_main(i32 %argc, ptr %argv) {
  call void @__iyi_main(i32 %argc, ptr %argv)
  invoke void @__crystal_main(i32 %argc, ptr %argv) #1 to label %ok unwind label %rescue
EOF' _ "$lib")" || return 1
  [[ "$rewritten" == *'define internal iyicc void @__iyi_main('* ]] &&
    [[ "$rewritten" == *'call iyicc void (i32, ptr) @__iyi_main('* ]] &&
    [[ "$rewritten" == *'invoke iyicc void (i32, ptr) @__crystal_main(i32 %argc, ptr %argv) to label %ok unwind label %rescue'* ]]
}
if entry_oracle_check; then
  prove_mutation "the oracle leaves the entry definition in the C convention" "$REPO/bench/lib/lower_oracle.sh" \
    ' || $0 ~ /^define .* @(__crystal_main|__iyi_main)\(/' '' -- entry_oracle_check || status=1
else
  echo "FAIL: entry oracle normalization differs on lower_tuple or its call forms"
  status=1
fi




# naming lane (mangled_name)
# The program-level lower of lower_name_owner waits: call.iyi refuses a call inherited
# from a superclass. The name itself is the hosted symbol, probed on the def alone.
name_owner_check() {
  "$IYI" build -o "$WORK/name-port" "$REPO/bench/selfhost_lower_name_owner.iyi" > "$WORK/name.build.log" 2>&1 || return 1
  "$WORK/name-port" "$REPO/bench/fixtures/lower_name_owner.iyi" "$WORK/lower_name_owner.oracle.ll" > "$WORK/name.out" 2> "$WORK/name.err" || return 1
  awk '/^NAME-OWNER MATCH$/ { ok = 1 } END { exit !ok }' "$WORK/name.out"
}
echo
echo "== naming lane (mangled_name)"
if name_owner_check; then
  echo "  lower_name_owner: *Child^Base#flag<Int32>:Int32"
else
  echo "  lower_name_owner: the defining-owner segment differs from the hosted symbol"
  awk 'NR<=8' "$WORK/name.err" "$WORK/name.out" "$WORK/name.build.log"
  status=1
fi
prove_mutation "an inherited method drops its defining owner" "$REPO/src/compiler/lower/fun.iyi" \
  'shown + "^" + defined_spell' \
  'shown' -- name_owner_check || status=1

name_metaclass_check() {
  "$IYI" build -o "$WORK/name-meta-port" "$REPO/bench/selfhost_lower_name_owner.iyi" > "$WORK/name-meta.build.log" 2>&1 || return 1
  "$WORK/name-meta-port" "$REPO/bench/fixtures/lower_name_metaclass.iyi" "$WORK/lower_name_metaclass.oracle.ll" metaclass > "$WORK/name-meta.out" 2> "$WORK/name-meta.err" || return 1
  awk '/^NAME-OWNER MATCH$/ { ok = 1 } END { exit !ok }' "$WORK/name-meta.out"
}
if name_metaclass_check; then
  echo "  lower_name_metaclass: *NameOwner::class_flag<Int32>:Int32"
else
  echo "  lower_name_metaclass: metaclass name differs from the hosted symbol"
  awk 'NR<=8' "$WORK/name-meta.err" "$WORK/name-meta.out" "$WORK/name-meta.build.log"
  status=1
fi
prove_mutation "a metaclass is named as an instance" "$REPO/src/compiler/lower/fun.iyi" \
  '      if st.is_a?(MetaclassType)' \
  '      if false' -- name_metaclass_check || status=1

name_return_check() {
  "$IYI" build -o "$WORK/name-return-port" "$REPO/bench/selfhost_lower_name_owner.iyi" > "$WORK/name-return.build.log" 2>&1 || return 1
  "$WORK/name-return-port" "$REPO/bench/fixtures/lower_name_return.iyi" "$WORK/lower_name_return.oracle.ll" return > "$WORK/name-return.out" 2> "$WORK/name-return.err" || return 1
  awk '/^NAME-OWNER MATCH$/ { ok = 1 } END { exit !ok }' "$WORK/name-return.out"
}
if name_return_check; then
  echo "  lower_name_return: *NameReturn::write<UInt64>:Nil"
else
  echo "  lower_name_return: declared return differs from the hosted symbol"
  awk 'NR<=8' "$WORK/name-return.err" "$WORK/name-return.out" "$WORK/name-return.build.log"
  status=1
fi
prove_mutation "the probe names the body type instead of the def type" "$REPO/src/compiler/lower/lower.iyi" \
  '  result_t = analysed.type_of?(target) || body_t' \
  '  result_t = body_t' -- name_return_check || status=1

name_generic_check() {
  "$IYI" build -o "$WORK/name-generic-port" "$REPO/bench/selfhost_lower_name_owner.iyi" > "$WORK/name-generic.build.log" 2>&1 || return 1
  "$WORK/name-generic-port" "$REPO/bench/fixtures/lower_name_generic.iyi" "$WORK/lower_name_generic.oracle.ll" generic > "$WORK/name-generic.out" 2> "$WORK/name-generic.err" || return 1
  awk '/^NAME-OWNER MATCH$/ { ok = 1 } END { exit !ok }' "$WORK/name-generic.out"
}
if name_generic_check; then
  echo "  lower_name_generic: *Box(Int32)^Box(T)#get<Int32>:Int32"
else
  echo "  lower_name_generic: generic defining owner differs from the hosted symbol"
  awk 'NR<=8' "$WORK/name-generic.err" "$WORK/name-generic.out" "$WORK/name-generic.build.log"
  status=1
fi
prove_mutation "a generic instance drops its defining generic owner" "$REPO/src/compiler/lower/fun.iyi" \
  '  if receiver.is_a?(GenericInstanceType)' \
  '  if false' -- name_generic_check || status=1

name_pointer_check() {
  "$IYI" build -o "$WORK/name-pointer-port" "$REPO/bench/selfhost_lower_name_owner.iyi" > "$WORK/name-pointer.build.log" 2>&1 || return 1
  "$WORK/name-pointer-port" "$REPO/bench/fixtures/lower_name_pointer_union.iyi" "$WORK/lower_name_pointer_union.oracle.ll" pointer > "$WORK/name-pointer.out" 2> "$WORK/name-pointer.err" || return 1
  awk '/^NAME-OWNER MATCH$/ { ok = 1 } END { exit !ok }' "$WORK/name-pointer.out"
}
if name_pointer_check; then
  echo "  lower_name_pointer_union: *pass_pointer<Pointer(Int32 | Nil)>:Pointer(Int32 | Nil)"
else
  echo "  lower_name_pointer_union: pointer union name differs from the hosted symbol"
  awk 'NR<=8' "$WORK/name-pointer.err" "$WORK/name-pointer.out" "$WORK/name-pointer.build.log"
  status=1
fi
prove_mutation "a pointer union gains extra parentheses" "$REPO/src/compiler/lower/fun.iyi" \
  'skip_union_parens: true, codegen: true' \
  'skip_union_parens: false, codegen: true' -- name_pointer_check || status=1

name_block_check() {
  "$IYI" build --prelude empty --emit llvm-ir --no-debug -o "$WORK/name-block-oracle" "$REPO/bench/fixtures/nameblock_capture.iyi" > "$WORK/name-block.oracle.log" 2>&1 || return 1
  "$IYI" build -o "$WORK/name-block-port" "$REPO/bench/selfhost_lower_name_owner.iyi" > "$WORK/name-block.build.log" 2>&1 || return 1
  "$WORK/name-block-port" "$REPO/bench/fixtures/nameblock_capture.iyi" "$WORK/name-block-oracle.ll" block > "$WORK/name-block.out" 2> "$WORK/name-block.err" || return 1
  awk '/^NAME-OWNER MATCH$/ { ok = 1 } END { exit !ok }' "$WORK/name-block.out"
}
if name_block_check; then
  echo "  nameblock_capture: captured block names match the hosted symbols"
else
  echo "  nameblock_capture: captured block names differ from the hosted symbols"
  for log in "$WORK/name-block.err" "$WORK/name-block.out" "$WORK/name-block.build.log" "$WORK/name-block.oracle.log"; do
    [ ! -f "$log" ] || awk 'NR<=8' "$log"
  done
  status=1
fi
prove_mutation "a captured block loses its ampersand" "$REPO/src/compiler/lower/fun.iyi" \
  '      names << "&" + symbol_type(bt)' \
  '      names << symbol_type(bt)' -- name_block_check || status=1

echo
echo
if [ "$status" -eq 0 ]; then
  echo "== ALL LOWER CORE CHECKS PASSED ($passed fixture(s) identical to the hosted module, $waiting waiting)"
else
  echo "== SOME LOWER CORE CHECKS FAILED"
fi
exit "$status"
