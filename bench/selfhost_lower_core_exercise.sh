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

# Writes the forms LLVM 22 leaves out and the port's text form requires, into a printed LLVM module:
# the function type of each direct call, from the types of its arguments, and the `label`
# keyword before each block of a phi's incoming pairs. Adds the function type to each direct call of a printed LLVM module, from the types
# of its arguments: `call T @f(A, B)` becomes `call T (typeA, typeB) @f(A, B)`. A
# call through a value, or one with an argument whose type is more than one word, is
# left as LLVM printed it, and the port then refuses the module by name.
CALL_TYPES='
function call_types(line,   p, rest, ret, after, op, cl, args, tail, n, parts, w, types, i, head, name) {
  p = index(line, " call ")
  if (p == 0) return line
  head = substr(line, 1, p + 5)
  rest = substr(line, p + 6)
  n = split(rest, w, " ")
  ret = w[1]
  after = substr(rest, length(ret) + 2)
  if (substr(after, 1, 1) != "@") return line
  op = index(after, "(")
  cl = index(after, ")")
  if (op == 0 || cl < op) return line
  name = substr(after, 1, op - 1)
  args = substr(after, op + 1, cl - op - 1)
  tail = substr(after, cl + 1)
  if (substr(tail, 1, 2) == " #") tail = ""
  n = split(args, parts, ", ")
  types = ""
  for (i = 1; i <= n; i++) {
    split(parts[i], w, " ")
    types = types (i > 1 ? ", " : "") w[1]
  }
  return head ret " (" types ") " name "(" args ")" tail
}
{
  if (index($0, " phi ") > 0) gsub(/, %/, ", label %")
  if (index($0, " call ") > 0) print call_types($0); else print
}
'

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
  if [ -n "$total" ] && [ "$total" -gt 0 ] && [ "$identical" = "$total" ]; then
    echo "    $name: PASSED, $identical of $total functions identical"
    passed=$((passed + 1))
  else
    echo "    $name: DIVERGED, $identical of $total functions identical"
    diverged=$((diverged + 1))
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
echo "== 3. Mutation proofs: the gate must catch each patch to the ported code"
# The check rebuilds the driver from the patched source and requires the nil fixture
# to match the hosted module exactly, and the context checks to hold. It returns 0 only
# on the unmutated behaviour.
lower_core_check() {
  "$IYI" build -o "$WORK/port-m" "$REPO/bench/selfhost_lower_core_exercise.iyi" > "$WORK/m.build.log" 2>&1 || return 1
  "$WORK/port-m" context > "$WORK/m.ctx" 2>&1 || return 1
  awk '/^CONTEXT OK$/ { ok = 1 } END { exit !ok }' "$WORK/m.ctx" || return 1
  for n in lower_nil lower_int lower_bool lower_assign lower_if; do "$WORK/port-m" lower "$REPO/bench/fixtures/$n.iyi" "$WORK/$n.oracle.ll" > "$WORK/m.out" 2> "$WORK/m.err" || return 1; awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); exit !(a[2] == b[2] \&\& a[2] > 0) }' "$WORK/m.out" || return 1; done
  awk '/^SUMMARY/ { split($2, a, "="); split($3, b, "="); exit !(a[2] == b[2] && a[2] > 0) }' "$WORK/m.out"
}
prove_mutation "argv is stored from the argc parameter" "$REPO/src/compiler/lower/lower.iyi" \
  "store_aligned(low, fn.param(1), argv_global)" "store_aligned(low, fn.param(0), argv_global)" -- lower_core_check || status=1
prove_mutation "main returns 1" "$REPO/src/compiler/lower/lower.iyi" \
  "low.builder.ret(low.builder.const_int(i32, 0))" "low.builder.ret(low.builder.const_int(i32, 1))" -- lower_core_check || status=1
prove_mutation "the alloca block is named after the entry block" "$REPO/src/compiler/lower/context.iyi" \
  'new_blocks(["alloca", "entry"])' 'new_blocks(["entry", "alloca"])' -- lower_core_check || status=1
prove_mutation "a bool literal is false" "$REPO/src/compiler/lower/lower.iyi" \
  "return 1_i64" "return 0_i64" -- lower_core_check || status=1
prove_mutation "a store is aligned to one byte" "$REPO/src/compiler/lower/helpers.iyi" \
  "set_align(st, low.typer.align_of(value.type))" "set_align(st, 1)" -- lower_core_check || status=1
prove_mutation "the then and else branches are swapped" "$REPO/src/compiler/lower/lower.iyi" \
  "low.builder.cond_br(cond_value, then_block, else_block)" "low.builder.cond_br(cond_value, else_block, then_block)" -- lower_core_check || status=1
prove_mutation "an empty alloca block is kept" "$REPO/src/compiler/lower/context.iyi" \
  "current_fun.blocks.delete(alloca)" "alloca.name" -- lower_core_check || status=1

echo
if [ "$status" -eq 0 ]; then
  echo "== ALL LOWER CORE CHECKS PASSED ($passed fixture(s) identical to the hosted module, $waiting waiting)"
else
  echo "== SOME LOWER CORE CHECKS FAILED"
fi
exit "$status"
