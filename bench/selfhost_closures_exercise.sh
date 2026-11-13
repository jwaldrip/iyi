#!/usr/bin/env bash
# Compare lexical closure facts with the hosted compiler on the same fixture prelude.
# Floors only rise once proven on a green head. The semclos_local WIP-only 4
# counted an external lib fun, which has no body or lexical frame; corrected to 3.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
. "$REPO/bench/lib/mutation.sh"
PRELUDE_PATH="$REPO/bench/fixtures/semclos_prelude:$REPO/src"
export CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src"
ORACLE="$WORK/oracle"
PORT="$WORK/port"
FLOOR="$REPO/bench/selfhost_closures.floor"

printf '%s\n' '== 1. Building the oracle and closure facts driver'
if ! "$REPO/bin/crystal" build -Di_know_what_im_doing -o "$ORACLE" "$REPO/bench/selfhost_closure_oracle.cr" > "$WORK/oracle.log" 2>&1; then
  awk 'NR<=30' "$WORK/oracle.log"
  exit 1
fi
build_port() {
  "$REPO/bin/iyi" build -o "$PORT" "$REPO/bench/selfhost_closures_exercise.iyi" > "$WORK/port.log" 2>&1 || { awk 'NR<=30' "$WORK/port.log"; return 1; }
}
build_port || exit 1
if ! "$PORT" > "$WORK/self-check.log" 2>&1; then
  awk 'NR<=30' "$WORK/self-check.log"
  exit 1
fi

compare_fixtures() {
  local fixture rel expected count
  for fixture in bench/fixtures/semclos_*.iyi; do
    rel="$fixture"
    IYI_PATH="$PRELUDE_PATH" "$ORACLE" "$fixture" > "$WORK/oracle.out" 2> "$WORK/oracle.err" || { awk 'NR<=10' "$WORK/oracle.err"; return 1; }
    "$PORT" "$fixture" > "$WORK/port.out" 2> "$WORK/port.err" || { awk 'NR<=10' "$WORK/port.err"; return 1; }
    if ! diff -u "$WORK/oracle.out" "$WORK/port.out"; then
      printf 'DIFFERENT: %s\n' "$rel"
      return 1
    fi
    count=$(awk 'END {print NR+0}' "$WORK/oracle.out")
    expected=$(awk -v name="$rel" '$1 == name { print $2 }' "$FLOOR")
    if [ -z "$expected" ] || [ "$count" != "$expected" ] || [ "$count" -eq 0 ]; then
      printf 'FLOOR MISMATCH: %s %s expected %s\n' "$rel" "$count" "${expected:-missing}"
      return 1
    fi
    printf '  %s: %s identical frames\n' "$rel" "$count"
  done
}

printf '%s\n' '== 2. Comparing closure facts'
compare_fixtures || exit 1
refusal_check() {
  "$PORT" --refusals bench/fixtures/semclos_literal_changing.iyi > "$WORK/refusals.out" 2>&1 || return 1
  awk '/^refusal: closured variable value assigned values of more than one type$/ { found=1 } END { exit !found }' "$WORK/refusals.out" || return 1
  "$PORT" --refusals bench/fixtures/semclos_refusals/nested.iyi > "$WORK/refusals.out" 2>&1 || return 1
  awk '/^refusal: nested proc literal$/ { found=1 } END { exit !found }' "$WORK/refusals.out" || return 1
  "$PORT" --refusals bench/fixtures/semclos_refusals/struct_self.iyi > "$WORK/refusals.out" 2>&1 || return 1
  awk '/^refusal: self of a struct type captured$/ { found=1 } END { exit !found }' "$WORK/refusals.out"
}
if ! refusal_check; then
  printf '%s\n' 'MISSING REFUSAL: changing captured variable type'
  exit 1
fi
mutation_check() {
  build_port && compare_fixtures && refusal_check
}

printf '%s\n' '== 3. Mutation proofs'
status=0
prove_mutation 'captured variable is omitted' "$REPO/src/compiler/semantic/closures.iyi" \
  'binding.captured = true' 'binding.captured = false' -- mutation_check || status=1
prove_mutation 'literal parameter does not shadow its outer variable' "$REPO/src/compiler/semantic/closures.iyi" \
  'proc_def.args.each do |arg|' '([] of Compiler::Syntax::Ast::Arg).each do |arg|' -- mutation_check || status=1
prove_mutation 'assignment does not declare a local' "$REPO/src/compiler/semantic/closures.iyi" \
  'elsif type = @visitor.type_of?(variable) || @visitor.type_of?(node.value)
        @frame.bindings << ClosureBinding.new(ClosureVar.new(variable.name, type))' \
  'elsif type = @visitor.type_of?(variable) || @visitor.type_of?(node.value)
        nil' -- mutation_check || status=1
prove_mutation 'typed declarations do not introduce bindings' "$REPO/src/compiler/semantic/closures.iyi" \
  'elsif type = @visitor.type_of?(variable)
        @frame.bindings << ClosureBinding.new(ClosureVar.new(variable.name, type))' \
  'elsif type = @visitor.type_of?(variable)
        nil' -- mutation_check || status=1
prove_mutation 'uninitialized declarations do not introduce bindings' "$REPO/src/compiler/semantic/closures.iyi" \
  'variable = node.var.as(Var)
      if type = @visitor.type_of?(variable)
        @frame.bindings << ClosureBinding.new(ClosureVar.new(variable.name, type))' \
  'variable = node.var.as(Var)
      if type = @visitor.type_of?(variable)
        nil' -- mutation_check || status=1
prove_mutation 'out arguments do not introduce bindings' "$REPO/src/compiler/semantic/closures.iyi" \
  'if type = @visitor.type_of?(variable)
          @frame.bindings << ClosureBinding.new(ClosureVar.new(variable.name, type))' \
  'if type = @visitor.type_of?(variable)
          nil' -- mutation_check || status=1
prove_mutation 'possibly unassigned captured locals lose Nil' "$REPO/src/compiler/semantic/closures.iyi" \
  'if type.nilable? && !binding.variable.type.nilable?' 'if false && type.nilable? && !binding.variable.type.nilable?' -- mutation_check || status=1
prove_mutation 'nested proc refusal is suppressed' "$REPO/src/compiler/semantic/closures.iyi" \
  'refuse_inside_proc("nested proc literal", false)' 'nil' -- mutation_check || status=1
prove_mutation 'struct self refusal is suppressed' "$REPO/src/compiler/semantic/closures.iyi" \
  'frame.errors << "self of a struct type captured" if self_type.struct?' \
  'frame.errors << "self of a struct type captured" if false && self_type.struct?' -- mutation_check || status=1
prove_mutation 'blocks are independent closure contexts' "$REPO/src/compiler/semantic/closures.iyi" \
  'while current.kind == FrameKind::Block' 'while false && current.kind == FrameKind::Block' -- mutation_check || status=1
prove_mutation 'instance variable does not capture self' "$REPO/src/compiler/semantic/closures.iyi" \
  'def visit(node : InstanceVar) : Bool
    capture_self' 'def visit(node : InstanceVar) : Bool
    nil' -- mutation_check || status=1
prove_mutation 'receiverless inherited call does not capture self' "$REPO/src/compiler/semantic/closures.iyi" \
  'capture_self if self_type.subtype_of?(owner)' 'capture_self if false && self_type.subtype_of?(owner)' -- mutation_check || status=1
prove_mutation 'reassignment after capture is not mutable' "$REPO/src/compiler/semantic/closures.iyi" \
  'elsif assignment && binding.captured' 'elsif false && assignment && binding.captured' -- mutation_check || status=1
prove_mutation 'changing captured variable is not refused' "$REPO/src/compiler/semantic/closures.iyi" \
  'if binding.assigned_types.size > 1' 'if false && binding.assigned_types.size > 1' -- mutation_check || status=1
prove_mutation 'shadowed parameters lose outer insertion order' "$REPO/src/compiler/semantic/closures.iyi" \
  'parent.visible_names' '[] of String' -- mutation_check || status=1
prove_mutation 'loop assignment is not mutable' "$REPO/src/compiler/semantic/closures.iyi" \
  'binding.variable.mutably = true if @inside_while' 'binding.variable.mutably = false if @inside_while' -- mutation_check || status=1
prove_mutation 'captured block argument is omitted from its def frame' "$REPO/src/compiler/semantic/closures.iyi" \
  'if block_arg = def_node.block_arg' 'if block_arg = (false ? def_node.block_arg : nil)' -- mutation_check || status=1
prove_mutation 'block locals are owned by the enclosing frame' "$REPO/src/compiler/semantic/closures.iyi" \
  'node.body.accept(ClosureWalk.new(@facts, @visitor, frame, @inside_while))' 'node.body.accept(ClosureWalk.new(@facts, @visitor, @frame, @inside_while))' -- mutation_check || status=1
prove_mutation 'a proc that captures a variable has no closure context' "$REPO/src/compiler/semantic/closures.iyi" \
  'break if part.node.node_id == owner_context.node.node_id
            part.closure = true if part.kind == FrameKind::Proc' \
  'break if part.node.node_id == owner_context.node.node_id
            part.closure = false if part.kind == FrameKind::Proc' -- mutation_check || status=1
prove_mutation 'program frame omits captured thread block' "$REPO/src/compiler/semantic/closures.iyi" \
  'roots << {frame, "top"} if frame.kind == FrameKind::Program' 'roots << {frame, "top"} if false && frame.kind == FrameKind::Program' -- mutation_check || status=1
if [ "$status" -ne 0 ]; then
  printf '%s\n' '== SOME CLOSURE CHECKS FAILED'
  exit 1
fi
printf '%s\n' '== ALL CLOSURE CHECKS PASSED'
