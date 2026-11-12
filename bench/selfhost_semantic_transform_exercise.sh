#!/usr/bin/env bash
# Fails when the iyi transformers stop agreeing with the hosted ones they replace.
#
# Slice S1e of the native self-host (SPEC.md Phase S). The hosted transformers
# are src/compiler/iyi/semantic/{normalizer,literal_expander,cleanup_transformer,
# math_interpreter}.cr; the port lives in src/compiler/semantic/{normalizer,
# literal_expander,cleanup,math_interpreter}.iyi. Every fixture bench/fixtures/
# semtx_*.iyi is parsed, rewritten by the oracle (the hosted pipeline) and by the
# port, both dumped with the same AST printer, and required byte-identical.
# A check that ran only the port would pass for a transformer that rewrote
# nothing at all.
#
# Transform table: hosted transform -> port, as of this increment
# (every row is the normalizer; "not ported" names what the gate cannot see):
#   Program#normalize            NormalizerProgram.normalize          ported
#                                macro_expansion (skip of the expansion's
#                                own Expressions/Defer lowering)      not ported:
#                                needs the VirtualFile location check and
#                                MainVisitor#iyi_splice_macro_defers
#   Expressions                  transform(Expressions)               ported
#   Defer                        transform(Defer)                     ported
#   apply_defers                 apply_defers                         ported
#   Call (group, super, cmp)     transform(Call)                      ported
#   Call group propagated flag   expand_iyi_group(node, propagated)   ported
#   Def (block arg pruning)      transform(Def)                       ported
#   Macro                        transform(Macro)                     ported
#   If                           transform(If)                        ported
#   Propagate (!)                transform(Propagate)                 ported
#                                (error_construct "end!"); iyi_bang_call
#                                not ported: IsA has no such field
#   Recover                      transform(Recover)                   ported
#   Unless                       transform(Unless)                    ported
#   Until                        transform(Until)                     ported
#   Assign                       transform(Assign)                    ported
#   OpAssign (call/index/simple) transform(OpAssign) + helpers        ported
#   StringInterpolation          transform(StringInterpolation)       ported
#   Block (unpacks)              transform(Block)                     ported (fixed:
#                                the body merge duplicated the unpacks and a
#                                single-expression body was dropped)
#   Union                        transform(Union)                     ported
#
# Mutation proofs follow the rule the other selfhost gates use: each patched
# file is compared against the original, and a patch that matched nothing is
# reported as proving nothing rather than passing quietly.
#
#   bash bench/selfhost_semantic_transform_exercise.sh
set -u
status=0
diverged=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
NORM="$REPO/src/compiler/semantic/normalizer.iyi"
PORT_DRIVER="$REPO/bench/selfhost_semantic_transform_exercise.iyi"
ORACLE_SRC="$REPO/bench/selfhost_semantic_transform_oracle.cr"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"

# The port and the hosted oracle each carry one AST printer, in their own
# driver file: bench/selfhost_semantic_transform_exercise.iyi and
# bench/selfhost_semantic_transform_oracle.cr. Both print every node kind the
# normalizer gate prints, in the same layout, and both list TypeOf, which the
# expander writes for every untyped literal (an unlisted class would print
# only its name on one side). The gate reads no other gate's files, so moving
# a line in the normalizer gate cannot break this one.

echo "== 1. Building the port driver and the hosted oracle"
cp "$PORT_DRIVER" "$WORK/semtx_port.iyi"
cp "$ORACLE_SRC" "$WORK/semtx_oracle.cr"
if ! grep -qF "when TypeOf" "$WORK/semtx_port.iyi" || ! grep -qF "when Iyi::TypeOf" "$WORK/semtx_oracle.cr"; then
  echo "  the AST printer is missing from the driver files"
  exit 1
fi
"$IYI" build -o "$WORK/port_exercise" "$WORK/semtx_port.iyi" || { echo "  PORT DRIVER DOES NOT BUILD"; exit 1; }
LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" \
  CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
    -o "$WORK/dump_crystal" "$WORK/semtx_oracle.cr" || { echo "  HOSTED ORACLE DOES NOT BUILD"; exit 1; }
if [ ! -x "$WORK/dump_crystal" ]; then
  echo "  HOSTED ORACLE DOES NOT BUILD"
  exit 1
fi

echo
echo "== 2. Rewritten tree comparison against the hosted transformers"
fixture_count=0
total_matched_nodes=0
for fixture in "$REPO"/bench/fixtures/semtx_*.iyi; do
  fixture_name="bench/fixtures/$(basename "$fixture")"
  "$WORK/port_exercise" "$fixture" > "$WORK/iyi.ast" 2>"$WORK/iyi.err" || {
    echo "  $fixture_name: PORT FAILED"; cat "$WORK/iyi.err"; diverged=$((diverged + 1)); status=1; fixture_count=$((fixture_count + 1)); continue; }
  IYI_PATH="$REPO/src" "$WORK/dump_crystal" "$fixture" > "$WORK/oracle.ast" 2>"$WORK/oracle.err" || {
    echo "  $fixture_name: HOSTED ORACLE FAILED"; cat "$WORK/oracle.err"; diverged=$((diverged + 1)); status=1; fixture_count=$((fixture_count + 1)); continue; }
  if ! cmp -s "$WORK/iyi.ast" "$WORK/oracle.ast"; then
    echo "  $fixture_name: REWRITTEN TREES DIFFER"
    diverged=$((diverged + 1))
    diff -u "$WORK/oracle.ast" "$WORK/iyi.ast" | head -40
    status=1
  else
    nodes_count=$(IYI_PATH="$REPO/src" "$WORK/dump_crystal" "$fixture" --count)
    echo "  $fixture_name: identical ($nodes_count rewritten nodes match the hosted transformers)"
    total_matched_nodes=$((total_matched_nodes + nodes_count))
  fi
  fixture_count=$((fixture_count + 1))
done
echo "  Parity summary: $((fixture_count - diverged))/$fixture_count fixtures rewrite identically ($total_matched_nodes total nodes)"

echo
echo "== 3. Mutation proofs: each one must make the comparison above fail"
# A patch to the port that the gate must catch. The port driver is rebuilt
# from the patched normalizer and compared with the hosted oracle on every
# fixture; a build failure or any differing tree counts as caught.
MUTATIONS_RUN=0
check_transform_agrees() {
  "$IYI" build -o "$WORK/mut_port" "$WORK/semtx_port.iyi" > /dev/null 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/semtx_*.iyi; do
    "$WORK/mut_port" "$fixture" > "$WORK/mut_iyi.ast" 2> /dev/null || return 1
    IYI_PATH="$REPO/src" "$WORK/dump_crystal" "$fixture" > "$WORK/mut_crystal.ast" || return 1
    cmp -s "$WORK/mut_iyi.ast" "$WORK/mut_crystal.ast" || return 1
  done
  return 0
}

MUTATIONS_RUN=$((MUTATIONS_RUN + 1))
prove_mutation "a group under a propagated bang keeps its join" "$NORM" 'rewritten << Call.new(group_var.clone, "join").at(node) unless propagated' 'rewritten << Call.new(group_var.clone, "join").at(node)' -- check_transform_agrees || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))
prove_mutation "a bang on a group does not mark it propagated" "$NORM" '@propagating_group = true' '@propagating_group = false' -- check_transform_agrees || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))
prove_mutation "the propagated mark is never consumed" "$NORM" 'propagated = @propagating_group' 'propagated = false' -- check_transform_agrees || status=1
echo "  $MUTATIONS_RUN mutation proofs run"

echo
echo "== 4. Math folding: the port's math interpreter against the hosted one"
MATH="$REPO/src/compiler/semantic/math_interpreter.iyi"
MATH_DRIVER="$REPO/bench/selfhost_semantic_math_exercise.iyi"
MATH_ORACLE_SRC="$REPO/bench/selfhost_semantic_math_oracle.cr"
LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" \
  CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
    -o "$WORK/math_oracle" "$MATH_ORACLE_SRC" > "$WORK/math_oracle.log" 2>&1 || { echo "  HOSTED MATH ORACLE DOES NOT BUILD"; cat "$WORK/math_oracle.log"; exit 1; }
"$IYI" build -o "$WORK/math_port" "$MATH_DRIVER" > "$WORK/math_port.log" 2>&1 || { echo "  MATH PORT DRIVER DOES NOT BUILD"; cat "$WORK/math_port.log"; exit 1; }
math_count=0
math_diverged=0
math_matched=0
for fixture in "$REPO"/bench/fixtures/semtx_math_*.iyi; do
  name="bench/fixtures/$(basename "$fixture")"
  if [ "$(basename "$fixture")" = "semtx_math_refused.iyi" ]; then continue; fi
  math_count=$((math_count + 1))
  "$WORK/math_port" "$fixture" > "$WORK/math_iyi.txt" 2> "$WORK/math_iyi.err" || {
    echo "  $name: MATH PORT FAILED"; cat "$WORK/math_iyi.err"; math_diverged=$((math_diverged + 1)); status=1; continue; }
  "$WORK/math_oracle" "$fixture" > "$WORK/math_oracle.txt" 2> "$WORK/math_oracle.err" || {
    echo "  $name: HOSTED MATH ORACLE FAILED"; cat "$WORK/math_oracle.err"; math_diverged=$((math_diverged + 1)); status=1; continue; }
  if cmp -s "$WORK/math_iyi.txt" "$WORK/math_oracle.txt"; then
    n=$(grep -c ': value=\|: error=' "$WORK/math_oracle.txt")
    echo "  $name: identical ($n expressions fold to the same value or message)"
    math_matched=$((math_matched + n))
  else
    echo "  $name: FOLDS DIFFER"
    diff -u "$WORK/math_oracle.txt" "$WORK/math_iyi.txt" | head -40
    math_diverged=$((math_diverged + 1))
    status=1
  fi
done
echo "  Parity summary: math $((math_count - math_diverged))/$math_count fixtures fold identically ($math_matched expressions)"

# The refused fixture: the port must refuse every expression by name, so the
# hosted answer is not compared on it. A line that is answered instead fails.
REFUSED="$REPO/bench/fixtures/semtx_math_refused.iyi"
if "$WORK/math_port" "$REFUSED" > "$WORK/math_refused.txt" 2>/dev/null \
   && [ "$(grep -c ': refused=' "$WORK/math_refused.txt")" -eq "$(grep -cv '^#\|^$' "$REFUSED")" ] \
   && ! grep -qv ': refused=' "$WORK/math_refused.txt"; then
  echo "  bench/fixtures/semtx_math_refused.iyi: every expression refused by name ($(grep -c ': refused=' "$WORK/math_refused.txt") lines)"
else
  echo "  bench/fixtures/semtx_math_refused.iyi: A LINE WAS ANSWERED, NOT REFUSED"
  cat "$WORK/math_refused.txt"
  status=1
fi

# A patch to the port's math interpreter that the gate must catch. The math
# driver is rebuilt from the patched module and compared with the oracle on
# every compared fixture; a build failure or a differing line counts as caught.
check_math_agrees() {
  "$IYI" build -o "$WORK/math_mut_port" "$MATH_DRIVER" > /dev/null 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/semtx_math_*.iyi; do
    if [ "$(basename "$fixture")" = "semtx_math_refused.iyi" ]; then continue; fi
    "$WORK/math_mut_port" "$fixture" > "$WORK/math_mut.txt" 2> /dev/null || return 1
    "$WORK/math_oracle" "$fixture" > "$WORK/math_mut_oracle.txt" 2> /dev/null || return 1
    cmp -s "$WORK/math_mut.txt" "$WORK/math_mut_oracle.txt" || return 1
  done
  return 0
}
MATH_MUTATIONS=0
MATH_MUTATIONS=$((MATH_MUTATIONS + 1))
prove_mutation "a wrapped result keeps the bits above its kind" "$MATH" 'low = value & mask_of(kind)' 'low = value' -- check_math_agrees || status=1
MATH_MUTATIONS=$((MATH_MUTATIONS + 1))
prove_mutation "a right shift past the width loses the sign of a negative value" "$MATH" 'MathValue.new(value.value < 0_i128 ? -1_i128 : 0_i128, value.kind)' 'MathValue.new(0_i128, value.kind)' -- check_math_agrees || status=1
MATH_MUTATIONS=$((MATH_MUTATIONS + 1))
prove_mutation "a result one above the kind's limit is accepted" "$MATH" 'return MathError.new("Arithmetic overflow") if magnitude > upper_magnitude(kind)' 'return MathError.new("Arithmetic overflow") if magnitude > upper_magnitude(kind) + 1_u128' -- check_math_agrees || status=1
MATH_MUTATIONS=$((MATH_MUTATIONS + 1))
prove_mutation "a mixed-signedness divisor is not wrapped to the left kind" "$MATH" 'if kind.signed? != right.kind.signed?' 'if false' -- check_math_agrees || status=1
MATH_MUTATIONS=$((MATH_MUTATIONS + 1))
prove_mutation "the MIN / -1 overflow carries the wrong message" "$MATH" '"Overflow: #{kind_name(kind)}::MIN / -1"' '"Overflow: #{kind_name(kind)}::MIN/-1"' -- check_math_agrees || status=1
echo "  $MATH_MUTATIONS math mutation proofs run"

echo
echo "== 5. Literal expansion: range literals, the port's walk against the hosted walk"
# The literal fixtures (semtx_lit_*.iyi) are walked by the port (the driver's
# `literals` mode) and by the hosted walk (the oracle's `literals` mode), and
# the rewritten trees must match. Range literals, string interpolations and array
# literals are lowered so far.
# An interpolation made only of literal pieces is kept out of these fixtures:
# the hosted parser folds it into one string (consume_interpolation in
# src/compiler/iyi/syntax/parser.cr), and the port's parser keeps the pieces.
# That is the parser's divergence, not the expander's, so every adjacency case
# here carries a variable piece.
LITERAL="$REPO/src/compiler/semantic/literal_expander.iyi"
lit_count=0
lit_diverged=0
for fixture in "$REPO"/bench/fixtures/semtx_lit_*.iyi; do
  name="bench/fixtures/$(basename "$fixture")"
  lit_count=$((lit_count + 1))
  "$WORK/port_exercise" "$fixture" literals > "$WORK/lit_iyi.ast" 2> "$WORK/lit_iyi.err" || {
    echo "  $name: LITERAL PORT FAILED"; cat "$WORK/lit_iyi.err"; lit_diverged=$((lit_diverged + 1)); status=1; continue; }
  IYI_PATH="$REPO/src" "$WORK/dump_crystal" "$fixture" literals > "$WORK/lit_oracle.ast" 2> "$WORK/lit_oracle.err" || {
    echo "  $name: HOSTED LITERAL WALK FAILED"; cat "$WORK/lit_oracle.err"; lit_diverged=$((lit_diverged + 1)); status=1; continue; }
  if cmp -s "$WORK/lit_iyi.ast" "$WORK/lit_oracle.ast"; then
    echo "  $name: identical (the literal walk lowers the same trees as the hosted walk)"
  else
    echo "  $name: LITERAL TREES DIFFER"
    diff -u "$WORK/lit_oracle.ast" "$WORK/lit_iyi.ast" | head -40
    lit_diverged=$((lit_diverged + 1))
    status=1
  fi
done
echo "  Parity summary: literal $((lit_count - lit_diverged))/$lit_count fixtures lower identically"

# A patch to the port's literal expander that the gate must catch. The copy of
# the port driver made at the start is rebuilt from the patched module and
# walked over every literal fixture; a difference or a failed build is caught.
check_literals_agree() {
  "$IYI" build -o "$WORK/lit_mut_port" "$WORK/semtx_port.iyi" > /dev/null 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/semtx_lit_*.iyi; do
    "$WORK/lit_mut_port" "$fixture" literals > "$WORK/lit_mut.ast" 2> /dev/null || return 1
    IYI_PATH="$REPO/src" "$WORK/dump_crystal" "$fixture" literals > "$WORK/lit_mut_oracle.ast" || return 1
    cmp -s "$WORK/lit_mut.ast" "$WORK/lit_mut_oracle.ast" || return 1
  done
  return 0
}
LIT_MUTATIONS=0
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "a range literal's exclusive flag is inverted" "$LITERAL" 'BoolLiteral.new(node.exclusive)' 'BoolLiteral.new(!node.exclusive)' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "a range literal names the wrong global type" "$LITERAL" 'Path.global(["Range"] of String)' 'Path.global(["Ranges"] of String)' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "a range nested in a range is not lowered" "$LITERAL" 'call.transform(self)' 'call' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "adjacent string literals are not merged" "$LITERAL" 'if piece.is_a?(StringLiteral) && next_piece.is_a?(StringLiteral)' 'if false' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "a merged literal keeps only the next piece's text" "$LITERAL" 'joined = piece.as(StringLiteral).value + next_piece.as(StringLiteral).value' 'joined = next_piece.as(StringLiteral).value' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "a merged literal joins its pieces in reverse" "$LITERAL" 'joined = piece.as(StringLiteral).value + next_piece.as(StringLiteral).value' 'joined = next_piece.as(StringLiteral).value + piece.as(StringLiteral).value' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "the last pair of a run is not merged" "$LITERAL" 'if i < n - 1' 'if i < n - 2' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "a typed empty array takes the typeof, not its type" "$LITERAL" 'type_var = of' 'type_var = typeof_exp(node.elements, temps)' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "the splat capacity counts the splats" "$LITERAL" 'capacity = count_non_splat(node.elements)' 'capacity = node.elements.size' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "buffer indices start at one" "$LITERAL" 'NumberLiteral.new(i.to_s), value_or_temp' 'NumberLiteral.new((i + 1).to_s), value_or_temp' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "every element is bound to a temporary" "$LITERAL" 'if plain_operand?(elem)' 'if false' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "a named splat block variable takes a plain temporary name" "$LITERAL" 'yield_var = temp_var_for(elem)' 'yield_var = temp_var' -- check_literals_agree || status=1
LIT_MUTATIONS=$((LIT_MUTATIONS + 1))
prove_mutation "the walk stops at the array expansion" "$LITERAL" 'expanded.transform(self)' 'expanded' -- check_literals_agree || status=1
echo "  $LIT_MUTATIONS literal mutation proofs run"

echo
if [ "$status" -eq 0 ]; then
  echo "ALL SELFHOST SEMANTIC TRANSFORM CHECKS PASSED SUCCESSFULLY!"
else
  echo "SELFHOST SEMANTIC TRANSFORM CHECKS FAILED"
fi
exit $status
