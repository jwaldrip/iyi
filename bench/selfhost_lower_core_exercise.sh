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
# Fixtures whose module differs from the hosted one for a reason named in NEEDS.md, not yet fixed. The port numbers
# String 31 and the hosted module 1 for lower_string and lower_string_nonascii (the typer slice's LowerTypeIds
# numbering, NEEDS.md row 16). They wait by name; the gate fails if one starts to match, so this list is kept honest.
KNOWN_DIVERGED="lower_string lower_string_nonascii"
e2e=""
module_same=0
module_differ=0
diverged=0
waiting=0
for fixture in "$REPO"/bench/fixtures/lower_*.iyi; do
  name="$(basename "$fixture" .iyi)"
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
CORE_CHECK_FIXTURES="lower_nil lower_int lower_bool lower_assign lower_if lower_char lower_while lower_break lower_unless lower_fold lower_cond_int lower_return lower_return_last lower_typedecl lower_typedecl_nil lower_fun_nil lower_fun_unused lower_implicit_self lower_fun_iyi lower_uint64_big lower_proc_literal"
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

echo
if [ "$status" -eq 0 ]; then
  echo "== ALL LOWER CORE CHECKS PASSED ($passed fixture(s) identical to the hosted module, $waiting waiting)"
else
  echo "== SOME LOWER CORE CHECKS FAILED"
fi
exit "$status"
