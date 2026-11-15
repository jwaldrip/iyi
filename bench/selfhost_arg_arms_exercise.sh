#!/usr/bin/env bash
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
export IYI_PATH="$REPO/src"
IYI="${IYI_COMPILER:-$REPO/bin/iyi}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"

check_arms() {
  "$IYI" build -o "$WORK/probe" "$REPO/bench/selfhost_arg_arms_probe.iyi" > "$WORK/build.log" 2>&1 || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_union_overload.iyi" "$REPO/src" consume > "$WORK/union" || return 1
  printf '%s\n' 'arms=2 cover=true' 'main#consume:Int32' 'main#consume:String' > "$WORK/expected"
  cmp -s "$WORK/union" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_order.iyi" "$REPO/src" show > "$WORK/order" || return 1
  printf '%s\n' 'arms=2 cover=true' 'main#show:A' 'main#show:Node+' > "$WORK/expected"
  cmp -s "$WORK/order" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_partial.iyi" "$REPO/src" consume > "$WORK/partial" || return 1
  printf '%s\n' 'arms=1 cover=false' 'main#consume:Int32' > "$WORK/expected"
  cmp -s "$WORK/partial" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_uncovered.iyi" "$REPO/src" consume > "$WORK/uncovered" || return 1
  printf '%s\n' 'arms=2 cover=false' 'main#consume:Int32,Bool' 'main#consume:String,String' > "$WORK/expected"
  cmp -s "$WORK/uncovered" "$WORK/expected" || return 1
  "$IYI" run "$REPO/bench/fixtures/sem_arms_uncovered.iyi" > "$WORK/oracle" 2>&1 && return 1
  grep -Fq "expected argument #1 to 'consume'" "$WORK/oracle" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_generic_new.iyi" "$REPO/src" new > "$WORK/generic" || return 1
  printf '%s\n' 'arms=1 cover=true' 'Box(T).class#new:UInt64' 'owner=Box(UInt64).class' > "$WORK/expected"
  cmp -s "$WORK/generic" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_generic_new_mismatch.iyi" "$REPO/src" new > "$WORK/mismatch" || return 1
  printf '%s\n' 'arms=0 cover=false' > "$WORK/expected"
  cmp -s "$WORK/mismatch" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_named_new.iyi" "$REPO/src" new > "$WORK/named" || return 1
  printf '%s\n' 'arms=1 cover=true' 'Stream.class#new:Int64' 'owner=Stream.class' > "$WORK/expected"
  cmp -s "$WORK/named" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_named_new_mismatch.iyi" "$REPO/src" new > "$WORK/named-mismatch" || return 1
  printf '%s\n' 'arms=0 cover=false' > "$WORK/expected"
  cmp -s "$WORK/named-mismatch" "$WORK/expected" || return 1
  for kind in module trait; do
    "$WORK/probe" "$REPO/bench/fixtures/sem_arms_${kind}_arg.iyi" "$REPO/src" show > "$WORK/$kind" || return 1
    printf '%s\n' 'arms=2 cover=true' 'main#show:A' 'main#show:(A | B)' > "$WORK/expected"
    cmp -s "$WORK/$kind" "$WORK/expected" || return 1
  done
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_module_walk.iyi" "$REPO/src" select modules > "$WORK/modules" || return 1
  printf '%s\n' 'arms=1 cover=false' 'Label#select:String' > "$WORK/expected"
  cmp -s "$WORK/modules" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_numeric.iyi" "$REPO/src" widen > "$WORK/numeric" || return 1
  printf '%s\n' 'arms=1 cover=true' 'main#widen:Int64' > "$WORK/expected"
  cmp -s "$WORK/numeric" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_tuple_index.iyi" "$REPO/src" '[]' > "$WORK/tuple" || return 1
  printf '%s\n' 'arms=1 cover=true' 'main#[]:Int32' > "$WORK/expected"
  cmp -s "$WORK/tuple" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_tuple_invalid.iyi" "$REPO/src" '[]' > "$WORK/tuple-invalid" || return 1
  printf '%s\n' 'arms=0 cover=false' 'error=index out of bounds for Tuple(Int32, String) (5 not in -2..1)' > "$WORK/expected"
  cmp -s "$WORK/tuple-invalid" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_numeric_ambiguous.iyi" "$REPO/src" widen > "$WORK/numeric-ambiguous" || return 1
  printf '%s\n' 'arms=0 cover=false' 'error=ambiguous call, implicit cast of 1 matches all of Int64, UInt64' > "$WORK/expected"
  cmp -s "$WORK/numeric-ambiguous" "$WORK/expected" || return 1
  "$IYI" run "$REPO/bench/fixtures/sem_arms_numeric_ambiguous.iyi" > "$WORK/ambiguous-oracle" 2>&1 && return 1
  grep -Fq 'ambiguous call, implicit cast of 1 matches all of Int64, UInt64' "$WORK/ambiguous-oracle" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_numeric_parent.iyi" "$REPO/src" widen > "$WORK/numeric-parent" || return 1
  printf '%s\n' 'arms=1 cover=true' 'Child#widen:Int64' > "$WORK/expected"
  cmp -s "$WORK/numeric-parent" "$WORK/expected" || return 1
  "$IYI" run "$REPO/bench/fixtures/sem_arms_numeric_parent.iyi" > "$WORK/numeric-parent-oracle" 2>&1 || return 1
  grep -Fxq 1 "$WORK/numeric-parent-oracle" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_unresolved.iyi" "$REPO/src" consume > "$WORK/unresolved" || return 1
  printf '%s\n' 'arms=1 cover=true' 'main#consume:Int32' > "$WORK/expected"
  cmp -s "$WORK/unresolved" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_unresolved_partial.iyi" "$REPO/src" consume > "$WORK/unresolved-partial" || return 1
  printf '%s\n' 'arms=1 cover=false' 'main#consume:Int32' > "$WORK/expected"
  cmp -s "$WORK/unresolved-partial" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_unresolved_only.iyi" "$REPO/src" consume > "$WORK/unresolved-only" || return 1
  printf '%s\n' 'arms=0 cover=false' 'error=undefined constant MissingType' > "$WORK/expected"
  cmp -s "$WORK/unresolved-only" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_block_output.iyi" "$REPO/src" produce > "$WORK/block" || return 1
  printf '%s\n' 'arms=1 cover=true' 'main#produce:' > "$WORK/expected"
  cmp -s "$WORK/block" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_capture_output.iyi" "$REPO/src" capture > "$WORK/capture" || return 1
  printf '%s\n' 'arms=1 cover=true' 'main#capture:' > "$WORK/expected"
  cmp -s "$WORK/capture" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_block_unbound.iyi" "$REPO/src" produce > "$WORK/block-unbound" || return 1
  printf '%s\n' 'arms=0 cover=false' 'error=undefined constant V' > "$WORK/expected"
  cmp -s "$WORK/block-unbound" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_bare_splat_named.iyi" "$REPO/src" pick > "$WORK/bare" || return 1
  printf '%s\n' 'arms=1 cover=true' 'Bare.class#pick:Int32' > "$WORK/expected"
  cmp -s "$WORK/bare" "$WORK/expected" || return 1
  for kind in missing excess; do
    "$WORK/probe" "$REPO/bench/fixtures/sem_arms_bare_splat_${kind}.iyi" "$REPO/src" pick > "$WORK/bare-$kind" || return 1
    printf '%s\n' 'arms=0 cover=false' > "$WORK/expected"
    cmp -s "$WORK/bare-$kind" "$WORK/expected" || return 1
  done
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_named_splat_tail.iyi" "$REPO/src" pick > "$WORK/named-tail" || return 1
  printf '%s\n' 'arms=0 cover=false' 'error=parameters after a named splat are not ported' > "$WORK/expected"
  cmp -s "$WORK/named-tail" "$WORK/expected" || return 1
}

check_arms || exit 1
"$IYI" build -o "$WORK/compiler" "$REPO/src/compiler/tools/compile_native.iyi" > "$WORK/compiler-build.log" 2>&1 || exit 1
if [ "$(uname -s)" = Darwin ]; then
  codesign -v --strict "$WORK/compiler" || exit 1
fi
IYI_ARGDISPATCH_TRACE=1 "$WORK/compiler" "$REPO/bench/fixtures/sem_arms_nil_eq.iyi" \
  -o "$WORK/nil" --pipeline typed --prelude --probe-phase > "$WORK/nil.log" 2>&1 || exit 1
grep -Fq 'targets=String#==(String);Reference#==(String);Object#==((String | Nil))' "$WORK/nil.log" || exit 1
IYI_ARGDISPATCH_TRACE=1 "$WORK/compiler" "$REPO/bench/fixtures/sem_arms_path_join.iyi" \
  -o "$WORK/path" --pipeline typed --prelude --probe-phase --keep-going > "$WORK/path.log" 2>&1 || true
grep -Fq 'targets=Std::Path::Path#join(String);Std::Path::Path#join(Std::Path::Path)' "$WORK/path.log" || exit 1
status=0
prove_mutation 'cover requires a matching arm for each combination' "$REPO/src/compiler/semantic/cover.iyi" \
  '        return true if accepted' '        return false if accepted' -- check_arms || status=1
prove_mutation 'stricter overload is inserted before broader overload' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  'while at < ordered.size && !arm_more_specific?(definition, ordered[at], args, owner)' \
  'while at < ordered.size' -- check_arms || status=1
prove_mutation 'generic metaclass restrictions use the bound instance' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '          match_owner = instance if instance.is_a?(GenericInstanceType)' \
  '          match_owner = owner if instance.is_a?(GenericInstanceType)' -- check_arms || status=1
prove_mutation 'generic match retains its metaclass owner' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '            arm = Match.new(match.definition, match.arg_types, owner, match.defining, match.exact, match.named_arg_types, match.declared, match.bound)' \
  '            arm = match' -- check_arms || status=1
prove_mutation 'named argument types participate in matching' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '      named_types = collected' \
  '      named_types = nil' -- check_arms || status=1
prove_mutation 'module-only walk does not search the superclass' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '      return Matches.new(matches, CallCover.all?(signature, matches)) if walk == ArmWalk::Modules && matches.size > level_start' \
  '      return Matches.new(matches, CallCover.all?(signature, matches)) if false' -- check_arms || status=1
prove_mutation 'unmatched numeric calls receive an autocast pass' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '    return found if found.error || !found.empty? || !NumericAutocast.any?(args, arg_types)' \
  '    return found' -- check_arms || status=1
prove_mutation 'tuple indexers keep their synthesized target' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '    if indexer.is_a?(Def)' \
  '    if false && indexer.is_a?(Def)' -- check_arms || status=1
prove_mutation 'tuple index errors remain errors' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '    if indexer.is_a?(String)' \
  '    if false && indexer.is_a?(String)' -- check_arms || status=1
prove_mutation 'unresolved restrictions are reported only when no arm matches' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '    return Matches.new(matches, false, first_error) if matches.empty? && first_error' \
  '    return Matches.new(matches, false, first_error) if first_error' -- check_arms || status=1
prove_mutation 'autocast compares every viable overload' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '          return Matches.new(matches, true) if arm.exact && signature.autocast_nodes.nil?' \
  '          return Matches.new(matches, true) if arm.exact' -- check_arms || status=1
prove_mutation 'a single successful autocast covers its call' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '    return Matches.new(widened.matches, true) if widened.error.nil? && widened.matches.size == 1' \
  '    return Matches.new(widened.matches, false) if widened.error.nil? && widened.matches.size == 1' -- check_arms || status=1
prove_mutation 'autocast stops after the first matching owner level' "$REPO/src/compiler/semantic/main_visitor.iyi" \
  '      if signature.autocast_nodes && matches.size > level_start' \
  '      if false' -- check_arms || status=1
prove_mutation 'a supplied block can bind free names in its output' "$REPO/src/compiler/semantic/match.iyi" \
  '                    deferred = FreeBindings.mentions?(output, [free_names[j]])' \
  '                    deferred = false' -- check_arms || status=1
prove_mutation 'bare splats allow named-only trailing parameters' "$REPO/src/compiler/semantic/match.iyi" \
  '      if count > k + 1 && !definition.args[k].name.empty?' \
  '      if count > k + 1' -- check_arms || status=1
prove_mutation 'bare splats reject excess positional arguments' "$REPO/src/compiler/semantic/match.iyi" \
  '    if splat && definition.args[splat.as(Int32)].name.empty? && given > prefix' \
  '    if false' -- check_arms || status=1
exit "$status"
