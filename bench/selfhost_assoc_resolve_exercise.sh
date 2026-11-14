#!/usr/bin/env bash
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
export IYI_PATH="$REPO/src"
IYI="${IYI_COMPILER:-$REPO/bin/iyi}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"

assoc_proof() {
  "$IYI" build -o "$WORK/compiler" "$REPO/src/compiler/tools/compile_native.iyi" > "$WORK/build.log" 2>&1 || return 1
  codesign -v --strict "$WORK/compiler" || return 1
  for name in sem_bodies_impl_assoc sem_bodies_impl_assoc_generic sem_bodies_impl_assoc_nested sem_bodies_impl_assoc_argument; do
    "$WORK/compiler" "$REPO/bench/fixtures/$name.iyi" -o "$WORK/$name" --pipeline typed --prelude --probe-phase > "$WORK/$name.log" 2>&1 || return 1
    codesign -v --strict "$WORK/$name" || return 1
    "$WORK/$name" > "$WORK/native.out" || return 1
    "$IYI" run "$REPO/bench/fixtures/$name.iyi" > "$WORK/hosted.out" || return 1
    cmp "$WORK/native.out" "$WORK/hosted.out" || return 1
  done
  "$WORK/compiler" "$REPO/bench/fixtures/refuse_bodies_impl_assoc_missing.iyi" -o "$WORK/missing" --pipeline typed --prelude --probe-phase > "$WORK/missing.log" 2>&1 && return 1
  grep -Fq 'does not answer an associated type the trait declares: Item' "$WORK/missing.log" || return 1
  "$IYI" run "$REPO/bench/selfhost_assoc_ast_probe.iyi" -- "$REPO/bench/fixtures/sem_bodies_impl_assoc_generic.iyi" > "$WORK/ast.out" || return 1
  grep -Fxq 'declarations=4 answers=2' "$WORK/ast.out"
}

assoc_proof || exit 1
status=0
prove_mutation 'impl parser records associated answers' "$REPO/src/compiler/syntax/parser.iyi" \
  '    assoc_types = collect_impl_assoc_types(body)' \
  '    assoc_types = nil' -- assoc_proof || status=1
prove_mutation 'impl visits associated declarations exactly once' "$REPO/src/compiler/syntax/ast.iyi" \
  '    @target.accept(visitor)
    @body.accept(visitor)' \
  '    @target.accept(visitor)
    if at = @assoc_types
      at.each { |a| a.accept(visitor) }
    end
    @body.accept(visitor)' -- assoc_proof || status=1
prove_mutation 'impl rejects an unanswered associated type' "$REPO/src/compiler/semantic/top_level.iyi" \
  '        unless found
          message = "impl #{trait_type.full_name} for #{target_type.full_name} does not answer an associated type the trait declares: #{name}"' \
  '        if false
          message = "impl #{trait_type.full_name} for #{target_type.full_name} does not answer an associated type the trait declares: #{name}"' -- assoc_proof || status=1
prove_mutation 'associated answers bind in receiver context' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '    unless bindings.empty?
      found = ArgRestriction.lookup_free(type_node_system(@program), @current_type, node, target, bindings)' \
  '    if false
      found = ArgRestriction.lookup_free(type_node_system(@program), @current_type, node, target, bindings)' -- assoc_proof || status=1
prove_mutation 'associated declarations lower to nil' "$REPO/src/compiler/lower/lower.iyi" \
  '  if node.is_a?(AssocTypeDecl)
    low.last = llvm_nil(low)
    return
  end' \
  '  if false
    low.last = llvm_nil(low)
    return
  end' -- assoc_proof || status=1
exit "$status"
