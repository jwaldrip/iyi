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
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_generic_new.iyi" "$REPO/src" new > "$WORK/generic" || return 1
  printf '%s\n' 'arms=1 cover=true' 'Box(T).class#new:UInt64' 'owner=Box(UInt64).class' > "$WORK/expected"
  cmp -s "$WORK/generic" "$WORK/expected" || return 1
  "$WORK/probe" "$REPO/bench/fixtures/sem_arms_generic_new_mismatch.iyi" "$REPO/src" new > "$WORK/mismatch" || return 1
  printf '%s\n' 'arms=0 cover=false' > "$WORK/expected"
  cmp -s "$WORK/mismatch" "$WORK/expected"
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
exit "$status"
